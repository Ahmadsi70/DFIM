# DFIM Platform Qualification (Phase 11)

## Scope

Phase 11 closes platform gates for:

- **AT-07** — TPM quote replay resistance with swtpm or hardware TPM evidence
- **AT-08** — Host recovery under power interruption and UEFI capsule recovery runbook

Repository automation proves AT-07 in CI via `tools/run_swtpm_attestation_gate.sh`. AT-08 remains a
destructive lab qualification documented by `tools/qualify_at08_power_loss.sh`.

## AT-07 — swtpm CI gate

```bash
export DFIM_CRYPTO_KEY="<org-controlled-material>"
export DFIM_TPM_TCTI="swtpm:host=127.0.0.1,port=2321"   # set automatically by gate script
bash tools/run_swtpm_attestation_gate.sh
```

Artifacts land in `artifacts/at07-swtpm/` including `at07-evidence.jsonl`.

Hardware qualification replaces `DFIM_TPM_TCTI` with `/dev/tpmrm0` and repeats the same CLI flow.

## AT-08 — power-loss host recovery

1. Run `bash tools/qualify_at08_power_loss.sh` to emit the planner and execute rollback safety tests.
2. On a disposable VM, interrupt `recover-v2` mid-commit.
3. Attach logs, verify output, and JSONL audit per `artifacts/qualify-at08/at08-power-loss-plan.md`.

## UEFI capsule path

Firmware recovery uses authenticated FMP capsules — see `UEFI_CAPSULE_RECOVERY.md`. Host
`recover-v2` does not replace capsule-based firmware update.

## Evidence checklist

| Gate | Required artifact |
|------|-------------------|
| AT-07 CI | `at07-evidence.jsonl` from swtpm gate |
| AT-07 hardware | Same CLI transcript + TPM event log |
| AT-08 | `at08-evidence.jsonl` + before/after verify |
| Capsule | Capsule sign-off record + platform `UpdateCapsule` log |
