# DFIM Production Packaging

## Purpose

Production deployments must not rely on the 30-day evaluation license (`.dfim_sys.dat`) as a
root of trust. Phase 8 introduces an explicit production packaging boundary so enterprise
contracts can require HSM-backed signing and host binaries that skip the evaluation gate.

## Host entry gate

All Ring-3 host binaries call `dfim_host_init::enforce_host_gate()` at startup.

| Build / runtime | Evaluation gate |
|-----------------|-----------------|
| Default dev build | Enforced (`enforce_eval_license`) |
| `cargo build --features production` | Skipped at compile time |
| `DFIM_PRODUCTION=1` (or `true`) at runtime | Skipped for dev builds |

Set `DFIM_PRODUCTION=1` only in controlled packaging pipelines after organizational
acceptance. Do not distribute dev builds with this variable set in shell profiles.

## Signing custody (HSM / KMS)

DFIMBOOT v2 sidecars must be signed with keys held in organizational custody:

- Prefer PKCS#11 HSM or cloud KMS with dual-control key ceremony.
- Never store production private keys on operator laptops or CI plaintext secrets.
- Rotate keys on compromise, personnel change, or contractually mandated intervals.
- Record each `release_counter` increment in change management.

The CLI accepts a local key file for lab use only. Production runbooks must document the
approved HSM/KMS integration path for your platform team.

## Windows release script

`build_windows_release.ps1` builds the provisioner with `--features production`:

```powershell
$env:DFIM_CRYPTO_KEY = '<org-controlled-material>'
$env:DFIM_PRODUCTION = '1'
.\build_windows_release.ps1
```

Artifacts are staged to the configured deployment Windows `bin/` directory or `$env:DFIM_DEPLOY_ROOT`.

## Automation stdout (`--format json`)

Verify, provision, and recovery subcommands accept global `--format json` for SOC automation.
Human-readable status remains on stderr; stdout emits one JSON object per invocation.

## Audit JSONL

When `DFIM_TELEMETRY_OUT` is set, provision success and failure emit `provision_v1` or
`provision_v2` records (schema version 1). See `TELEMETRY.md` for field definitions.

## Pilot acceptance

Internal pilot gate: one Windows asset provisioned with v2 signing, periodic verify with
JSONL audit, and at least one documented recovery drill.
