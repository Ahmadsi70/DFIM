# DFIM Offline Audit Report

Plain-English, English-only integrity report for demos, pilots, and air-gapped sites.

## Purpose

The host CLI remains the control plane. Audit JSONL is still the source of record. This tool
generates a **single self-contained HTML file** that opens offline (no CDN, no Docker) and explains,
in non-technical language, which **enrolled protected files** are healthy and which need attention.

## Generate a report

```bash
python tools/dfim_audit_report.py \
  --input /path/to/dfim_audit.jsonl \
  --output artifacts/reports/dfim-report.html \
  --catalog test_environment/sample-telemetry/assets.catalog.json
```

Set `DFIM_TELEMETRY_OUT` on the host CLI to produce audit JSONL, then pass that file to this tool.

## What non-technical readers see

| Section | Meaning |
|---------|---------|
| **Executive summary** | Plain English: how many protected files are healthy vs need attention |
| **Protected files** | Friendly name, status, last check, suggested action |
| **Healthy** | File matches the authorized baseline |
| **Unauthorized change** | Content no longer matches the enrolled baseline |
| **Execution blocked** | Linux runtime blocked a changed protected file |
| **Restored** | Authorized recovery completed |

The footer states clearly: **enrolled files only — not a full-system scan, not antivirus.**

## Friendly file names

Map pseudonymous `asset_id` values to human labels with `assets.catalog.json`:

```json
{
  "assets": {
    "sha256:abc...": {
      "name": "Primary boot image",
      "host": "pay-server-01"
    }
  }
}
```

Without a catalog, the report uses shortened asset IDs.

## Sample data

```bash
python tools/dfim_audit_report.py \
  -i test_environment/sample-telemetry/dfim_sample_audit.jsonl \
  -c test_environment/sample-telemetry/assets.catalog.json \
  -o artifacts/reports/sample-report.html
```

## When to use

| Scenario | Recommendation |
|----------|----------------|
| Enterprise SOC live | Forward JSONL via OpenTelemetry Collector |
| Pilot / tender demo | Generate HTML from lab JSONL |
| Air-gapped site | Periodic HTML export from local audit file |
| Executive briefing | Open HTML — executive summary is plain English |

## Security notes

- Reports contain redacted fields only (`asset_id` pseudonym, no paths or keys).
- Treat generated HTML like audit data: access-controlled storage and retention.
- This viewer is read-only; it does not modify policy or provision assets.

## CI

- Unit tests: `python tools/test_dfim_audit_report.py`
- Contract gate: `python tools/verify_offline_report_contract.py`
