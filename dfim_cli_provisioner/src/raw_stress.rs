//! Raw block-device validation harness — NIST SP 800-193 §4.2.3 cache bypass + fault injection.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use dfim_windows_uefi::{build_boot_sidecar, DFIM_BLOCK_SIZE};

use crate::platform::{
    block_byte_offset, flip_bit_at_offset, read_block_device, write_block_device,
};
use crate::verify::verify_image_bytes_against_state;
use crate::{map_dfim_error, run_integrity_gates};

/// Arguments for the `raw-stress` subcommand (QEMU / bare-metal Linux validation).
#[derive(Debug, Clone)]
pub struct RawStressArgs {
    pub device: PathBuf,
    pub golden: PathBuf,
    pub state: Option<PathBuf>,
    pub cycles: usize,
    pub inject_sector: Option<u64>,
    pub jsonl_out: PathBuf,
}

/// Runs validation cycles, optional bit-flip injection, and emits JSONL compliance telemetry.
pub fn run_raw_stress(args: &RawStressArgs) -> Result<(), String> {
    run_integrity_gates(&args.device)?;
    run_integrity_gates(&args.golden)?;

    let golden = fs::read(&args.golden).map_err(|err| {
        format!(
            "failed to read golden image {}: {err}",
            args.golden.display()
        )
    })?;
    if golden.is_empty() {
        return Err(format!("golden image is empty: {}", args.golden.display()));
    }

    let state_path = args
        .state
        .clone()
        .unwrap_or_else(|| default_sidecar_path(&args.golden));

    if !state_path.is_file() {
        let sidecar = build_boot_sidecar(&golden).map_err(map_dfim_error)?;
        if let Some(parent) = state_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "failed to create sidecar directory {}: {err}",
                        parent.display()
                    )
                })?;
            }
        }
        fs::write(&state_path, &sidecar).map_err(|err| {
            format!(
                "failed to write baseline sidecar {}: {err}",
                state_path.display()
            )
        })?;
    }

    let image_len = golden.len();

    write_block_device(&args.device, &golden[..image_len])?;

    let mut cycle_timings_ns = Vec::with_capacity(args.cycles);
    let cycle_start = Instant::now();
    for cycle in 0..args.cycles {
        let lap = Instant::now();
        let live = read_block_device(&args.device, image_len)?;
        verify_image_bytes_against_state(&live[..image_len], &state_path)?;
        cycle_timings_ns.push(lap.elapsed().as_nanos() as u64);
        if cycle > 0 && cycle % 100 == 0 {
            eprintln!("[raw-stress] cycle {cycle}/{} PASS", args.cycles);
        }
    }
    let cycles_elapsed_ms = cycle_start.elapsed().as_millis();

    append_jsonl(
        &args.jsonl_out,
        json_line(
            "RAW-CYCLES",
            "PASS",
            args,
            image_len,
            args.cycles,
            &cycle_timings_ns,
            cycles_elapsed_ms,
            None,
        ),
    )?;

    if let Some(sector) = args.inject_sector {
        let flip_offset = block_byte_offset(sector, DFIM_BLOCK_SIZE);
        let pre = Instant::now();
        flip_bit_at_offset(&args.device, flip_offset)?;
        let flip_ns = pre.elapsed().as_nanos() as u64;

        let post_read = read_block_device(&args.device, image_len)?;
        let fault_result = verify_image_bytes_against_state(&post_read[..image_len], &state_path);
        let fail_closed = fault_result.is_err();
        let status = if fail_closed { "PASS" } else { "FAIL" };
        append_jsonl(
            &args.jsonl_out,
            json_line(
                "RAW-FAULT-INJECT",
                status,
                args,
                image_len,
                1,
                &[flip_ns],
                flip_ns as u128 / 1_000_000,
                Some((sector, flip_offset, fail_closed)),
            ),
        )?;
        if !fail_closed {
            return Err(format!(
                "fail-closed violation: bit-flip at sector {sector} (offset {flip_offset}) \
                 did not reject verification"
            ));
        }
        eprintln!("[PASS] fail-closed: sector {sector} flip rejected (merkle drift detected)");
    }

    eprintln!(
        "[PASS] raw-stress device={} cycles={} bytes={} jsonl={}",
        args.device.display(),
        args.cycles,
        image_len,
        args.jsonl_out.display()
    );
    Ok(())
}

fn default_sidecar_path(golden: &Path) -> PathBuf {
    let mut out = golden.as_os_str().to_os_string();
    out.push(".dfim");
    PathBuf::from(out)
}

fn append_jsonl(path: &Path, line: String) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create jsonl directory {}: {err}",
                    parent.display()
                )
            })?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open jsonl {}: {err}", path.display()))?;
    writeln!(file, "{line}")
        .map_err(|err| format!("failed to write jsonl {}: {err}", path.display()))
}

#[allow(clippy::too_many_arguments)]
fn json_line(
    phase: &str,
    status: &str,
    args: &RawStressArgs,
    image_len: usize,
    cycles: usize,
    timings_ns: &[u64],
    elapsed_ms: u128,
    fault: Option<(u64, u64, bool)>,
) -> String {
    let min_ns = timings_ns.iter().copied().min().unwrap_or(0);
    let max_ns = timings_ns.iter().copied().max().unwrap_or(0);
    let avg_ns = if timings_ns.is_empty() {
        0
    } else {
        timings_ns.iter().copied().sum::<u64>() / timings_ns.len() as u64
    };
    let fault_json = match fault {
        Some((sector, offset, rejected)) => format!(
            r#","inject_sector":{sector},"inject_byte_offset":{offset},"fail_closed":{}"#,
            if rejected { "true" } else { "false" }
        ),
        None => String::new(),
    };
    format!(
        r#"{{"phase":"{phase}","status":"{status}","device":"{}","golden":"{}","image_bytes":{image_len},"cycles":{cycles},"timing_ns":{{"min":{min_ns},"max":{max_ns},"avg":{avg_ns}}},"elapsed_ms":{elapsed_ms}{fault_json}}}"#,
        args.device.display(),
        args.golden.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_contains_phase_and_timing_fields() {
        let args = RawStressArgs {
            device: PathBuf::from("/dev/vda"),
            golden: PathBuf::from("/tmp/golden.bin"),
            state: None,
            cycles: 10,
            inject_sector: None,
            jsonl_out: PathBuf::from("/tmp/out.jsonl"),
        };
        let line = json_line("RAW-CYCLES", "PASS", &args, 8192, 10, &[100, 200], 15, None);
        assert!(line.contains("\"phase\":\"RAW-CYCLES\""));
        assert!(line.contains("\"timing_ns\""));
    }

    #[test]
    fn default_sidecar_appends_dfim_extension() {
        let golden = PathBuf::from("/data/image.bin");
        assert_eq!(
            default_sidecar_path(&golden),
            PathBuf::from("/data/image.bin.dfim")
        );
    }

    #[test]
    fn fault_json_reports_fail_closed_true() {
        let args = RawStressArgs {
            device: PathBuf::from("/dev/vda"),
            golden: PathBuf::from("/tmp/golden.bin"),
            state: None,
            cycles: 1,
            inject_sector: Some(512),
            jsonl_out: PathBuf::from("/tmp/out.jsonl"),
        };
        let line = json_line(
            "RAW-FAULT-INJECT",
            "PASS",
            &args,
            4096,
            1,
            &[50],
            1,
            Some((512, block_byte_offset(512, DFIM_BLOCK_SIZE), true)),
        );
        assert!(line.contains("\"fail_closed\":true"));
    }
}
