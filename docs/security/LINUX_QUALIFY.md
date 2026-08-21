# DFIM Linux Runtime Qualification (Phase 9)

## Purpose

Documents the lab environment and evidence bundle required to pass adversarial tests **AT-01**
through **AT-04** on a supported Linux kernel before claiming Phase-1 runtime enforcement.

## Kernel and platform checklist

| Requirement | Verification |
|-------------|--------------|
| `CONFIG_DEBUG_INFO_BTF=y` | `test -e /sys/kernel/btf/vmlinux` |
| BPF LSM enabled | `grep bpf /sys/kernel/security/lsm` |
| IMA appraisal ready | `/sys/kernel/security/ima/policy` readable; enforce mode documented |
| Audit subsystem | `auditd` or equivalent for EPERM correlation |
| Disposable VM | snapshot restore between destructive cases |

## Qualification workflow

1. Build `dfim-ebpf-user` on the lab host (root required for attach).
2. Export `DFIM_TELEMETRY_OUT` to an append-only JSONL path.
3. Run `bash tools/qualify_at_linux.sh` to initialize the artifact directory.
4. Execute each AT case manually following `docs/security/ADVERSARIAL_ACCEPTANCE.md`.
5. Attach to the evidence bundle:
   - `qualify-at-summary.jsonl`
   - `DFIM_TELEMETRY_OUT` JSONL (includes `dfim.integrity.failure`, `dfim.metadata.corrupt`, `dfim.policy.deny`)
   - `dmesg`, audit log excerpt, and tested commit SHA

## AT mapping (current implementation)

| Test | Expected signal |
|------|-----------------|
| AT-01 | Exec returns EPERM; JSONL contains integrity or policy deny with `enforcement_layer=ebpf_lsm` |
| AT-02 | Unrelated binary runs; no deny event for unscoped inode |
| AT-03 | Protected asset remains denied after metadata/map deletion |
| AT-04 | Protected asset denied with `DenyInvalidConfig`; global outage does not occur |

## SIEM bridge

Runtime LSM denials are recorded through the `DFIM_DENY_EVENTS` ring buffer and persisted by
`deny_monitor` into the same `DFIM_TELEMETRY_OUT` file used by the host CLI. Forward that file
with the OpenTelemetry Collector configuration under `test_environment/otel-collector/`.

## Ops dashboard

Import `test_environment/ops-stack/grafana/dashboards/dfim-ops.json` after starting the local
stack documented in `test_environment/ops-stack/README.md`.
