# DFIM Enterprise Integration Guide

**Document ID:** DFIM-ENT-INTEG-2026-V1.0  
**Product:** Deterministic Firmware Integrity Matrix (DFIM)  
**Audience:** SOC Engineers, SIEM Administrators, Platform Architects  
**Classification:** Technical — Partner Integration

---

## 1. SOC & SIEM Integration Schema

DFIM emits structured security events when the integrity pipeline returns **`CorruptMetadata`** or **`IntegrityFailure`**. Integrators should ingest these events via syslog forwarder, Windows Event Log custom channel, or eBPF user-space loader stderr capture piped to a log shipper.

### 1.1 Event Types

| Event Type | Internal Error | MITRE-Oriented Category |
|------------|----------------|-------------------------|
| `dfim.integrity.failure` | `IntegrityFailure` | Tampering / Defense Evasion (T1553) |
| `dfim.metadata.corrupt` | `CorruptMetadata` | Data Manipulation / Stored Data Integrity (T1565) |

### 1.2 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO-8601 UTC | Event generation time |
| `host_ip` | string | IPv4/IPv6 of reporting host |
| `event_type` | string | `dfim.integrity.failure` or `dfim.metadata.corrupt` |
| `severity` | string | `critical` (IntegrityFailure) or `high` (CorruptMetadata) |
| `affected_block` | integer | Zero-based block index under verification (or `-1` if metadata-level) |
| `expected_merkle_root` | string (hex) | Authorized baseline root from sidecar / CMDB |
| `calculated_merkle_root` | string (hex) | Root computed from live image at detection time |
| `asset_path` | string | Protected binary or firmware path |
| `sidecar_path` | string | Associated `.dfim` sidecar path |
| `enforcement_layer` | string | `host` \| `uefi` \| `ebpf_lsm` |
| `action_taken` | string | `deny` \| `halt` \| `alert_only` |

### 1.3 JSON Payload — `IntegrityFailure` (Block Tamper Detected)

```json
{
  "schema_version": "1.0",
  "vendor": "DFIM",
  "product": "Deterministic Firmware Integrity Matrix",
  "event_type": "dfim.integrity.failure",
  "internal_error": "IntegrityFailure",
  "severity": "critical",
  "timestamp": "2026-06-27T14:32:18.447Z",
  "host_ip": "10.42.18.55",
  "hostname": "WIN-PROD-DC01.ooredoo.local",
  "enforcement_layer": "ebpf_lsm",
  "asset_path": "/opt/guarded/app-server",
  "sidecar_path": "/opt/guarded/app-server.dfim",
  "affected_block": 3,
  "block_size_bytes": 4096,
  "block_offset_bytes": 12288,
  "expected_merkle_root": "080b780c377c49b6dbdb4988becb729df294365a81873727c4e5f8a91d2b3c6e1f",
  "calculated_merkle_root": "c222cf604defa4d500c47f845fafb6b5dee05e5a8ae4819273a1b0c4d5e6f7a8",
  "image_size_bytes": 65536,
  "block_count": 16,
  "inode": 8847291,
  "action_taken": "deny",
  "message": "integrity verification failed",
  "correlation_id": "dfim-20260627-143218-7f3a9c"
}
```

### 1.4 JSON Payload — `CorruptMetadata` (FEC / Sidecar Corruption)

```json
{
  "schema_version": "1.0",
  "vendor": "DFIM",
  "product": "Deterministic Firmware Integrity Matrix",
  "event_type": "dfim.metadata.corrupt",
  "internal_error": "CorruptMetadata",
  "severity": "high",
  "timestamp": "2026-06-27T14:35:02.119Z",
  "host_ip": "10.42.18.55",
  "hostname": "WIN-PROD-DC01.ooredoo.local",
  "enforcement_layer": "host",
  "asset_path": "C:\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
  "sidecar_path": "C:\\EFI\\Microsoft\\Boot\\bootmgfw.efi.dfim",
  "affected_block": -1,
  "block_size_bytes": 4096,
  "block_offset_bytes": null,
  "expected_merkle_root": "080b780c377c49b6dbdb4988becb729df294365a81873727c4e5f8a91d2b3c6e1f",
  "calculated_merkle_root": "a91f2e8b4c6d7091e3f5a8b2c4d6e8f0a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8d",
  "fec_decode_status": "uncorrectable_multi_bit",
  "header_merkle_root": "080b780c377c49b6dbdb4988becb729df294365a81873727c4e5f8a91d2b3c6e1f",
  "fec_recovered_root": "a91f2e8b4c6d7091e3f5a8b2c4d6e8f0a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8d",
  "action_taken": "deny",
  "message": "corrupt metadata detected",
  "correlation_id": "dfim-20260627-143502-b8e1d4"
}
```

### 1.5 SIEM Field Mapping (Reference)

| SIEM (Splunk / Sentinel / Elastic) | DFIM JSON Field |
|------------------------------------|-----------------|
| `_time` / `TimeGenerated` | `timestamp` |
| `src_ip` / `HostIp` | `host_ip` |
| `signature` / `AlertName` | `event_type` |
| `severity` / `Level` | `severity` |
| Custom attribute | `expected_merkle_root` |
| Custom attribute | `calculated_merkle_root` |
| Custom attribute | `affected_block` |

### 1.6 Recommended Alert Rules

| Rule Name | Condition | Response |
|-----------|-----------|----------|
| DFIM Critical Integrity Failure | `event_type == "dfim.integrity.failure"` | P1 ticket, host isolation |
| DFIM Metadata Corruption | `event_type == "dfim.metadata.corrupt"` | P2 ticket, sidecar restore |
| DFIM Root Mismatch Repeat | Same `host_ip`, ≥3 events in 5 min | Escalate to SecOps |

---

## 2. Technical SLA Boundaries

### 2.1 Performance SLA Definition

| Metric | Bound | Measurement Context |
|--------|-------|-------------------|
| Merkle validation latency (idle) | **< 100 ms** | 16-block (65,536-byte) reference fixture |
| Merkle validation latency (stressed) | **< 100 ms** | 4 parallel CPU stress workers, 3-second window |
| Binary footprint | **~435 KB** combined (provisioner + UEFI guard) | Release build, stripped |
| Determinism | **100%** | Identical inputs → identical Merkle root |

### 2.2 Mandatory Host Power Configuration

**Requirement:** All SLA-bound validation hosts **must** operate under the Windows **High Performance** power plan for the duration of benchmark and production attestation windows.

**Activation command (authoritative GUID):**

```powershell
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
```

**Verification:**

```powershell
powercfg /getactivescheme
```

Expected active scheme name contains **High performance**.

### 2.3 SLA Exclusions — ACPI P-State Scaling

The following conditions are **explicitly excluded** from soft-SLA liability and do not constitute product defect:

| Excluded Condition | Typical Symptom | Operational Owner |
|--------------------|-----------------|-------------------|
| **ACPI P-state / core parking** enabled | Idle validation spikes >100 ms (observed up to ~653 ms pre-mitigation) | Infrastructure / Hypervisor |
| **Balanced or Power Saver** power plan active | Non-deterministic turbo ramp latency | Infrastructure |
| **CPU thermal throttling** | Sustained validation >100 ms under heat load | Hardware / Facilities |
| **Hypervisor CPU oversubscription** | Stressed benchmark variance >50% vs idle baseline | Virtualization team |
| **Antivirus real-time scan** on target binary during validation | Intermittent latency inflation | Endpoint Security |
| **Network-mounted assets** (NFS/SMB latency) | Not applicable to local Merkle math; affects provision I/O only | Storage team |

**Contract language (summary):** DFIM guarantees sub-100 ms Merkle verification **only when** the host is configured per Section 2.2 and exclusion conditions above are absent. Measurements taken under ACPI P-state scaling, core parking, or non-High-Performance power plans are **informational only** and shall not be used for SLA credit or defect claims.

### 2.4 Linux eBPF Path SLA Note

Kernel-side enforcement latency includes LSM hook dispatch and map lookup overhead. User-space provision and validation SLA (<100 ms) applies to `dfim-provisioner` and `dfim-ebpf-user` pre-attach validation. In-kernel deny path target: **< 1 ms** detection isolation for tampered blocks (audit reference).

---

## 3. Compatibility Matrix

Verified platform layers for DFIM PoC and enterprise pilot deployments. Status reflects Ooredoo trial validation cycle (2026-Q2).

| OS / Platform | Version | Component | DFIM Layer | BTF / UEFI | Verification Status | Notes |
|---------------|---------|-----------|------------|------------|---------------------|-------|
| **Windows Server** | 2019 (17763+) | `dfim-provisioner.exe` | Ring-3 Host | N/A | **Verified** | Full sidecar provision + dry-run |
| **Windows Server** | 2019 (17763+) | `dfim_windows_uefi.efi` | Ring-1 UEFI | UEFI 2.x | **Verified** | Boot guard intercept path |
| **Windows Server** | 2022 (20348+) | `dfim-provisioner.exe` | Ring-3 Host | N/A | **Verified** | Defender Enterprise clean scan |
| **Windows Server** | 2022 (20348+) | `dfim_windows_uefi.efi` | Ring-1 UEFI | UEFI 2.x | **Verified** | High Performance SLA met |
| **Windows Server** | 2025 (26100+) | `dfim-provisioner.exe` | Ring-3 Host | N/A | **Verified** | Pilot certification |
| **Windows Server** | 2025 (26100+) | `dfim_windows_uefi.efi` | Ring-1 UEFI | UEFI 2.x | **Verified** | Pilot certification |
| **Ubuntu LTS** | 22.04 (Jammy) | `dfim-ebpf` + `dfim-ebpf-user` | eBPF LSM CO-RE | `CONFIG_DEBUG_INFO_BTF=y` | **Verified** | WSL2 6.6.x kernel tested |
| **Ubuntu LTS** | 22.04 (Jammy) | `dfim-provisioner` (cross-build) | Ring-3 Host | N/A | **Verified** | Merkle parity with Windows |
| **Ubuntu LTS** | 24.04 (Noble) | `dfim-ebpf` + `dfim-ebpf-user` | eBPF LSM CO-RE | `CONFIG_DEBUG_INFO_BTF=y` | **Verified** | Native + container hosts |
| **Ubuntu LTS** | 24.04 (Noble) | `dfim-provisioner` (cross-build) | Ring-3 Host | N/A | **Verified** | Sidecar interchange compatible |
| **UEFI Firmware** | UEFI Guard **v2.1** extensions | `dfim_windows_uefi.efi` | Pre-boot integrity | Secure Boot compatible | **Verified** | Standard extension profile |
| **UEFI Firmware** | UEFI Guard **v2.1** extensions | `.dfim` sidecar (DFIMBOOT v1) | Metadata binding | N/A | **Verified** | 4096-byte block alignment |

### 3.1 Layer Capability Summary

| Capability | Windows Server | Ubuntu LTS | UEFI Guard v2.1 |
|------------|----------------|------------|-----------------|
| Sidecar generation (`dfim-provisioner`) | Yes | Yes (binary) | N/A (consumes sidecar) |
| Pre-boot enforcement | Via UEFI module | N/A | Yes |
| Runtime exec/module block (eBPF LSM) | N/A | Yes | N/A |
| Max image size | 262,144 bytes | 262,144 bytes | 262,144 bytes |
| Max Merkle proof depth | 16 steps | 16 steps | 16 steps |
| CO-RE BTF required | No | Yes (eBPF path) | No |

### 3.2 Unsupported / Out-of-Scope (Current Release)

| Platform | Reason |
|----------|--------|
| Windows Server 2016 and earlier | Untested UEFI guard stack |
| RHEL / CentOS Stream (without BTF) | eBPF CO-RE requirement unmet |
| macOS | No eBPF LSM equivalent |
| Images > 262 KB (64 blocks) | Layer-0 capacity cap |

---

## Document Control

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 1.0 | 2026-06-28 | DFIM Product Management | Initial enterprise integration release |

---

*End of Enterprise Integration Guide — DFIM-ENT-INTEG-2026-V1.0*
