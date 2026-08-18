//! Fork of `aya_build::build_ebpf` with an enlarged BPF stack for sha2 Merkle paths.

use std::{
    borrow::Cow,
    env,
    ffi::OsString,
    fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::{anyhow, Context as _, Result};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};

#[derive(Default)]
pub struct Package<'a> {
    pub name: &'a str,
    pub root_dir: &'a str,
    pub no_default_features: bool,
    pub features: &'a [&'a str],
}

pub enum Toolchain<'a> {
    Nightly,
    Custom(&'a str),
}

impl<'a> Toolchain<'a> {
    fn as_str(&self) -> &'a str {
        match self {
            Self::Nightly => "nightly",
            Self::Custom(toolchain) => toolchain,
        }
    }
}

fn target_arch_fixup(target_arch: Cow<'_, str>) -> Cow<'_, str> {
    if target_arch.starts_with("riscv64") {
        "riscv64".into()
    } else {
        target_arch
    }
}

/// Build eBPF binaries with BTF + enlarged BPF stack (sha2 exceeds 512 B default).
pub fn build_ebpf<'a>(
    packages: impl IntoIterator<Item = Package<'a>>,
    toolchain: Toolchain<'a>,
) -> Result<()> {
    let out_dir = env::var_os("OUT_DIR").ok_or(anyhow!("OUT_DIR not set"))?;
    let out_dir = PathBuf::from(out_dir);

    let endian =
        env::var_os("CARGO_CFG_TARGET_ENDIAN").ok_or(anyhow!("CARGO_CFG_TARGET_ENDIAN not set"))?;
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        return Err(anyhow!("unsupported endian={endian:?}"));
    };

    const TARGET_ARCH: &str = "CARGO_CFG_TARGET_ARCH";
    let bpf_target_arch =
        env::var_os(TARGET_ARCH).unwrap_or_else(|| panic!("{TARGET_ARCH} not set"));
    let bpf_target_arch = bpf_target_arch
        .into_string()
        .unwrap_or_else(|err| panic!("OsString::into_string({TARGET_ARCH}): {err:?}"));
    let bpf_target_arch = target_arch_fixup(bpf_target_arch.into());
    let target = format!("{target}-unknown-none");

    for Package {
        name,
        root_dir,
        no_default_features,
        features,
    } in packages
    {
        println!("cargo:rerun-if-changed={root_dir}");

        let mut cmd = Command::new("rustup");
        cmd.args([
            "run",
            toolchain.as_str(),
            "cargo",
            "build",
            "--package",
            name,
            "-Z",
            "build-std=core",
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target,
        ]);
        if no_default_features {
            cmd.arg("--no-default-features");
        }
        cmd.args(["--features", &features.join(",")]);

        {
            const SEPARATOR: &str = "\x1f";
            let mut rustflags = OsString::new();
            for s in [
                "--cfg=bpf_target_arch=\"",
                &bpf_target_arch,
                "\"",
                SEPARATOR,
                "-Cdebuginfo=2",
                SEPARATOR,
                "-Clink-arg=--btf",
                SEPARATOR,
                "-Cllvm-args=-bpf-stack-size=16384",
            ] {
                rustflags.push(s);
            }
            cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
        }

        for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }

        let target_dir = out_dir.join("bpf-target");
        cmd.arg("--target-dir").arg(&target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn {cmd:?}"))?;
        let Child { stdout, stderr, .. } = &mut child;

        let stderr = stderr.take().expect("stderr");
        let stderr = BufReader::new(stderr);
        let stderr = std::thread::spawn(move || {
            for line in stderr.lines() {
                let line = line.expect("read line");
                println!("cargo:warning={line}");
            }
        });

        let stdout = stdout.take().expect("stdout");
        let stdout = BufReader::new(stdout);
        let mut executables = Vec::new();
        for message in Message::parse_stream(stdout) {
            match message.expect("valid JSON") {
                Message::CompilerArtifact(Artifact {
                    executable: Some(executable),
                    target: Target { name, .. },
                    ..
                }) => {
                    executables.push((name, executable.into_std_path_buf()));
                }
                Message::CompilerMessage(CompilerMessage { message, .. }) => {
                    for line in message.rendered.unwrap_or_default().split('\n') {
                        println!("cargo:warning={line}");
                    }
                }
                Message::TextLine(line) => {
                    println!("cargo:warning={line}");
                }
                _ => {}
            }
        }

        let status = child
            .wait()
            .with_context(|| format!("failed to wait for {cmd:?}"))?;
        if !status.success() {
            return Err(anyhow!("{cmd:?} failed: {status:?}"));
        }

        match stderr.join().map_err(std::panic::resume_unwind) {
            Ok(()) => {}
            Err(err) => match err {},
        }

        for (name, binary) in executables {
            let dst = out_dir.join(name);
            if dst.is_dir() {
                fs::remove_dir_all(&dst)
                    .with_context(|| format!("failed to remove stale directory {dst:?}"))?;
            }
            fs::copy(&binary, &dst)
                .with_context(|| format!("failed to copy {binary:?} to {dst:?}"))?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    if env::var_os("DFIM_SKIP_EBPF_BUILD").is_some() {
        let out_dir = env::var_os("OUT_DIR").ok_or(anyhow!("OUT_DIR not set"))?;
        let placeholder = PathBuf::from(out_dir).join("dfim-ebpf");
        fs::write(&placeholder, b"DFIM-COMPILE-ONLY")
            .with_context(|| format!("write compile-only eBPF placeholder {placeholder:?}"))?;
        println!("cargo:warning=DFIM_SKIP_EBPF_BUILD is compile-only; resulting loader cannot run");
        println!("cargo:rerun-if-env-changed=DFIM_SKIP_EBPF_BUILD");
        return Ok(());
    }
    build_ebpf(
        [Package {
            name: "dfim-ebpf",
            root_dir: "../dfim-ebpf",
            ..Default::default()
        }],
        Toolchain::Nightly,
    )
}
