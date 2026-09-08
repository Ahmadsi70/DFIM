# DFIM Operations Manual

**Document ID:** DFIM-OPS-MANUAL-2026-V1.0  
**Audience:** Data Center / Platform Operations Engineers (Windows & Linux)  
**Classification:** Technical — Internal Use  
**Product:** Deterministic Firmware Integrity Matrix (DFIM)

---

## 1. Document Overview

### 1.1 Purpose

This runbook provides production troubleshooting procedures for DFIM deployments spanning:

- **Ring-3 Windows host provisioning** (`dfim-provisioner`)
- **Ring-1 UEFI boot guard** (`dfim_windows_uefi.efi`)
- **Linux kernel LSM enforcement** (`dfim-ebpf` + `dfim-ebpf-user`)

### 1.2 Architectural Properties

| Property | Description |
|----------|-------------|
| **Stateless validation** | Integrity checks are derived entirely from the on-disk image and its `.dfim` sidecar. No runtime database or session state is required. |
| **Deterministic output** | Identical inputs (image bytes + sidecar) always produce identical Merkle roots and pass/fail outcomes. |
| **Fixed binary footprint** | Combined production artifacts (`dfim-provisioner.exe` + `dfim_windows_uefi.efi`) target ~**435 KB** total overhead — suitable for air-gapped and constrained firmware environments. |
| **Layer-0 bounds** | Maximum guarded image: **262,144 bytes** (64 × 4,096-byte blocks). Maximum Merkle proof depth: **16 steps** (aligned across host, UEFI, and eBPF paths). |

### 1.3 Canonical Paths (Reference Deployment)

| Component | Path |
|-----------|------|
| Windows provisioner | `C:\DFIM\bin\dfim-provisioner.exe` |
| UEFI boot guard | `C:\DFIM\bin\dfim_windows_uefi.efi` |
| Windows stress / demo | `C:\DFIM\test_environment\run_stress_test.ps1` |
| DFIM workspace launcher | `C:\Users\badri\DFIM\test_environment\run_windows_stress_test.ps1` |
| Linux eBPF loader (build output) | `dfim_linux_kernel/dfim-ebpf-user` (WSL2 / native Linux) |
| Audit runbook | `C:\Users\badri\DFIM\test_environment\docs\DFIM_Audit_Runbook_Telecom.txt` |

### 1.4 Prerequisites

**Windows**

- PowerShell 5.1 or later
- High Performance power plan recommended for SLA-bound benchmarks (`powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c`)
- Execution policy allowing signed or trusted scripts (or launch with `-ExecutionPolicy Bypass`)

**Linux (eBPF path)**

- Kernel ≥ 5.15 with **BTF** enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- `bpftool`, `rustup` nightly, `bpf-linker` for builds
- Root or `CAP_BPF` + `CAP_SYS_ADMIN` for LSM attach
- WSL2 supported for development; production attach requires native Linux with LSM enabled

---

## 2. Standard Run Commands

### 2.1 Windows — Host Provisioner CLI

**Binary:** `dfim-provisioner.exe`  
**Crate source:** `dfim_cli_provisioner` → published binary name `dfim-provisioner`

#### Dry-run validation (no sidecar write)

```powershell
cd "C:\DFIM\test_environment"
..\bin\dfim-provisioner.exe .\fixtures\demo_boot_image.bin --dry-run
```

#### Provision sidecar (writes `<target>.dfim` by default)

```powershell
..\bin\dfim-provisioner.exe C:\path\to\bootmgfw.efi --output C:\path\to\bootmgfw.efi.dfim
```

#### Implicit output path (same directory as target)

```powershell
..\bin\dfim-provisioner.exe C:\EFI\Microsoft\Boot\bootmgfw.efi
```

#### Expected success indicators

- Exit code `0`
- Stdout includes Merkle root (64-char hex), block count, and proof statistics
- Sidecar file present at declared output path (when not using `--dry-run`)

#### Rebuild and redeploy (after source changes)

```powershell
cd C:\Users\badri\DFIM
cargo build --release -p dfim_cli_provisioner
Copy-Item -Force .\target\release\dfim-provisioner.exe `
  "C:\DFIM\bin\dfim-provisioner.exe"
```

---

### 2.2 Windows — Interactive Executive Demo

```powershell
# Canonical path
& "C:\DFIM\test_environment\run_stress_test.ps1"

# Legacy runbook alias (forwards to canonical script)
& "C:\Users\badri\DFIM\test_environment\run_windows_stress_test.ps1"
```

---

### 2.3 Linux — eBPF LSM Loader & Telemetry

**Binary:** `dfim-ebpf-user`  
**Kernel probe:** `dfim-ebpf` (CO-RE, maps: `DFIM_MANIFESTS`, `DFIM_PROOFS`, `DFIM_IMAGES`, `DFIM_SCRATCH`)

#### Build (WSL2 or native Linux)

```bash
cd /mnt/c/Users/badri/DFIM/dfim_linux_kernel/dfim-ebpf-user
cargo build --release
```

#### Attach probes (empty maps — passive load)

```bash
sudo ./target/release/dfim-ebpf-user load
```

#### Provision target + attach (production path)

```bash
sudo ./target/release/dfim-ebpf-user provision \
  --target /path/to/guarded-binary \
  --sidecar /path/to/guarded-binary.dfim
```

#### Kernel trace / telemetry hooks

```bash
# eBPF printk output (panic path, optional debug)
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -i dfim

# Verify probe attachment
sudo bpftool prog list | grep -E 'bprm_check_security|kernel_module_from_file'

# Inspect populated maps after provision
sudo bpftool map list | grep -i dfim
sudo bpftool map dump name DFIM_MANIFESTS
```

#### Concurrent map stress (audit validation)

```bash
for i in $(seq 1 200); do
  sudo bpftool map dump name DFIM_MANIFESTS > /dev/null &
done
wait
dmesg | tail -50 | grep -iE 'bpf|lock|collision'
```

#### Detach

Press `Ctrl-C` in the loader terminal (loader holds probes until interrupted).

---

## 3. Error Code Matrix

Internal errors originate from `dfim_core_engine::DfimError`. CLI tools surface these as human-readable strings on stderr.

| Internal Error | CLI / Log String | Root Cause | Resolution Steps |
|----------------|------------------|------------|------------------|
| **IntegrityFailure** | `integrity verification failed` | Merkle root mismatch; tampered image block; missing or wrong proof; sidecar/image block count mismatch; trailing garbage in sidecar blob | 1. Re-run `--dry-run` on golden image. 2. Compare emitted Merkle root against authorized baseline. 3. Verify `.dfim` matches exact image inode/path provisioned. 4. Regenerate sidecar with `dfim-provisioner` if image was legitimately updated. 5. If root changed without authorized patch → treat as **INCIDENT** (Section 4). |
| **BufferTooLong** | `buffer too long` | Image or staged file exceeds **262,144 bytes** (`MAX_IMAGE_BYTES`) or padded block count exceeds **64** | 1. Confirm file size: `(Get-Item $path).Length` (Windows) or `stat -c%s` (Linux). 2. Split or re-segment workload if policy allows; DFIM Layer-0 cap is fixed at 64 × 4 KiB. 3. Do not force-load oversized images into eBPF maps. |
| **CorruptMetadata** | `corrupt metadata detected` | Hamming FEC multi-bit corruption; FEC-decoded metadata disagrees with cleartext manifest header; silent re-root path blocked by strict codec | 1. Verify sidecar storage integrity (disk, replication lag). 2. Restore sidecar from last known-good backup. 3. Rebuild sidecar from trusted image: `dfim-provisioner <image> --output <image>.dfim`. 4. If corruption recurs on clean media → investigate storage subsystem or supply-chain tampering. |
| **CapacityOverflow** *(maps to `ParameterOverflow`)* | `parameter overflow` | Block count, inode key, proof depth, or sidecar dimensions exceed engine caps; arithmetic overflow in size calculations | 1. Confirm `block_count ≤ 64` and proof steps ≤ 16 per block. 2. On Linux, verify inode fits map key limits. 3. Re-provision with compliant image. 4. Upgrade is not available beyond Layer-0 caps — segment the protected asset or use host-only validation. |
| **BufferTooShort** | `buffer too short` | Truncated sidecar; incomplete proof payload; malformed DFIMBOOT header | 1. Validate sidecar file size > 56-byte header minimum. 2. Re-transfer sidecar (SCP/rsync corruption check). 3. Regenerate from source image. |
| **InvalidParameter** | `invalid parameter` | Wrong block size (≠ 4096); zero block count; proof depth > 16 in sidecar; invalid sidecar version | 1. Parse sidecar with `dfim-provisioner --dry-run`. 2. Confirm sidecar version `DFIMBOOT` v1. 3. Regenerate if parameters invalid. |
| **EmptyInput** | `empty input` | Zero-byte image or file read | 1. Confirm source file exists and is non-empty. 2. Check UEFI `read_volume_file` guard if boot guard rejects early. |
| **UncorrectableError** | `uncorrectable error detected` | Hamming codec detected uncorrectable bit pattern (legacy path) | 1. Treat as **CorruptMetadata** incident. 2. Replace sidecar from trusted source. |
| **WorkCapExceeded** | `computation work cap exceeded` | Pathological input size triggered internal observer cap | 1. Reduce input dimensions. 2. Retry with standard 16-block demo fixture. 3. Escalate to engineering if reproducible on compliant inputs. |

### 3.1 eBPF-Specific Failure Modes (No Internal Enum — Operational)

| Symptom | Likely Cause | Action |
|---------|--------------|--------|
| Loader fails: BTF required | Kernel built without `CONFIG_DEBUG_INFO_BTF` | Rebuild kernel or deploy on BTF-enabled host |
| `-EPERM` on exec of guarded binary | Validation failed in `enforce_dfim_integrity` | Check maps populated; re-run `provision`; verify image ≤ 262 KB |
| Probe load: stack limit | Stale probe binary | Rebuild `dfim-ebpf-user` from current workspace |
| `PathNotFound` on demo script | Wrong runbook path | Use `DFIM\test_environment\run_windows_stress_test.ps1` launcher or the canonical deployment path |

---

## 4. Incident Response — Merkle Root Change Detected

### 4.1 Severity Classification

| Classification | Description | Initial Severity |
|----------------|-------------|------------------|
| **P1 — Suspected Compromise** | Root changed on production boot/ELF asset with no approved change ticket | Critical |
| **P2 — Un coordinated Patch** | Root changed after legitimate binary update; sidecar not regenerated | High |
| **P3 — Environmental Drift** | Root mismatch on non-production fixture; demo/test asset | Medium |

---

### 4.2 Immediate Triage (First 15 Minutes)

**Step 1 — Capture evidence (do not overwrite)**

```powershell
$Asset = "C:\path\to\protected\binary"
$Sidecar = "$Asset.dfim"
Get-FileHash $Asset -Algorithm SHA256 | Format-List
Get-FileHash $Sidecar -Algorithm SHA256 | Format-List
..\bin\dfim-provisioner.exe $Asset --dry-run 2>&1 | Tee-Object -FilePath ".\dfim_root_capture_$(Get-Date -Format yyyyMMdd_HHmmss).log"
```

```bash
# Linux guarded asset
sha256sum /path/to/binary /path/to/binary.dfim
/path/to/dfim-ebpf-user provision --target /path/to/binary --sidecar /path/to/binary.dfim 2>&1 | tee /tmp/dfim_root_capture.log
```

**Step 2 — Compare against authorized baseline**

- Locate approved Merkle root from change record, `DFIM_Audit_Runbook_Telecom.txt`, or CMDB golden reference.
- If **live root == baseline** → false alarm; check for wrong file path or stale sidecar pointer.
- If **live root ≠ baseline** → proceed to Step 3.

**Step 3 — Determine change authorization**

| Signal | Likely Explanation |
|--------|-------------------|
| Active OS/firmware patch window; binary timestamp matches patch | **Uncoordinated patch** (P2) |
| Binary timestamp unchanged; root changed | **Tampering or storage corruption** (P1) |
| Only sidecar changed; binary hash stable | **Sidecar substitution** (P1) |
| Both binary and sidecar changed together with valid ticket | **Authorized update** — regenerate baseline |

---

### 4.3 Decision Tree: Ransomware / Firmware Attack vs Uncoordinated Patch

```
Merkle Root Changed
        |
        v
+---------------------------+
| Binary SHA256 changed?    |
+-----------+---------------+
            |
     +------+------+
     | NO          | YES
     v             v
Sidecar-only   +-----------------------------+
corruption     | Change ticket / patch window |
(P1)           | for this asset?              |
               +----+--------------+----------+
                    | NO           | YES
                    v              v
              P1 Suspected    +------------------+
              Compromise      | Vendor signature |
              ISOLATE ASSET   | / patch hash OK? |
              Preserve logs   +----+---------+---+
                                   | NO     | YES
                                   v        v
                              P1 Attack  P2 Patch
                              ISOLATE    Regenerate
                              Chain      sidecar +
                              analysis   update CMDB
```

---

### 4.4 Response Actions by Classification

#### P1 — Suspected Ransomware / Firmware Tampering

1. **Isolate** the host from production network (hypervisor port group quarantine or firewall deny).
2. **Preserve** binary, sidecar, and DFIM logs; do not reboot if memory forensics required.
3. **Deny boot/exec** — UEFI guard and eBPF LSM should return deny; confirm in logs.
4. **Escalate** to SOC / SecOps with captured Merkle roots and SHA-256 hashes.
5. **Do not** regenerate sidecar until forensic copy obtained.
6. Restore from **last known-good immutable backup** after clean-room verification.

#### P2 — Uncoordinated System Patch (Legitimate Binary Update)

1. Confirm patch source (WSUS, apt, vendor ISO, internal build pipeline).
2. Obtain **new authorized binary** from trusted distribution point.
3. Regenerate sidecar:

   ```powershell
   ..\bin\dfim-provisioner.exe C:\path\to\patched\binary.exe --output C:\path\to\patched\binary.exe.dfim
   ```

4. Re-validate:

   ```powershell
   ..\bin\dfim-provisioner.exe C:\path\to\patched\binary.exe --dry-run
   ```

5. Update CMDB golden Merkle root and close change record.
6. On Linux, re-run:

   ```bash
   sudo ./dfim-ebpf-user provision --target /path/to/patched/binary --sidecar /path/to/patched/binary.dfim
   ```

#### P3 — Test / Demo Fixture Drift

1. Regenerate fixture via `run_stress_test.ps1` or known test harness.
2. Document new root in test documentation only — **do not** update production baseline.

---

### 4.5 Post-Incident Verification Checklist

- [ ] Merkle root matches updated authorized baseline
- [ ] `--dry-run` exits 0 on all protected assets
- [ ] Sidecar `block_count` matches `ceil(image_size / 4096)`
- [ ] eBPF maps repopulated after Linux reprovision
- [ ] UEFI boot path tested on non-production hardware (if firmware involved)
- [ ] Change ticket / audit log updated
- [ ] SOC notified if P1 was triggered (even if later downgraded)

---

## 5. Quick Reference Constants

| Constant | Value |
|----------|-------|
| `DFIM_BLOCK_SIZE` | 4,096 bytes |
| `MAX_BOOT_BLOCKS` | 64 |
| `MAX_IMAGE_BYTES` | 262,144 bytes |
| `MAX_PROOF_STEPS` | 16 |
| Combined binary overhead (audit reference) | ~435 KB |
| SLA target (validation latency) | < 100 ms |

---

## 6. Escalation Contacts

| Tier | Team | When to Engage |
|------|------|----------------|
| L1 | Data Center Operations | First-line triage, command execution, log capture |
| L2 | Platform / Kernel Engineering | eBPF load failures, CO-RE offset mismatches, probe verifier errors |
| L3 | DFIM Engineering / Security Architecture | Merkle root policy, sidecar format changes, P1 compromise |

---

*End of Operations Manual — DFIM-OPS-MANUAL-2026-V1.0*
