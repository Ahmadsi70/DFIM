# DFIM Local Ops Stack (Phase 9)

Minimal Grafana + Loki stack for lab SOC demos. Tails the same JSONL audit file configured for
`DFIM_TELEMETRY_OUT`.

## Start

```bash
export DFIM_TELEMETRY_OUT=/path/to/dfim_audit.jsonl
touch "${DFIM_TELEMETRY_OUT}"
docker compose -f test_environment/ops-stack/docker-compose.yml up -d
```

Open Grafana at http://localhost:3000 and import the **DFIM Operations** dashboard from
`grafana/dashboards/dfim-ops.json` (auto-provisioned on startup).

## Panels

1. Verify volume (`verify_v1`)
2. eBPF policy deny volume (`dfim.policy.deny`)
3. Recovery volume (`recovery_v2`)
4. Provision vs integrity failure trend
5. Fail-closed sink errors (`FAIL-CLOSED` substring)

Production deployments should forward `DFIM_TELEMETRY_OUT` through the OpenTelemetry Collector
instead of Promtail when enterprise OTLP endpoints are available.

## Offline HTML report (no Docker)

For demos or air-gapped review without Grafana:

```bash
python tools/dfim_audit_report.py \
  -i "${DFIM_TELEMETRY_OUT}" \
  -c test_environment/sample-telemetry/assets.catalog.json \
  -o artifacts/reports/dfim-report.html
```

See `docs/enterprise/OFFLINE_REPORT.md`.
