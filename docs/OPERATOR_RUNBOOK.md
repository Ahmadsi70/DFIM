# DFIM Operator Runbook

## Quick Start

```bash
# Start API
DATABASE_URL=postgres://dfim:PASS@localhost/dfim_production \
DFIM_JWT_SECRET=your-256-bit-secret \
DFIM_API_BIND=0.0.0.0:3000 \
./dfim_management_api

# Health check
curl http://localhost:3000/health

# Login
curl -X POST http://localhost:3000/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"REDACTED"}'
```

## Daily Operations

| Task | Command |
|------|---------|
| Check fleet health | `curl http://localhost:3000/v1/fleet/summary` |
| List tampered assets | `curl http://localhost:3000/v1/assets?status=tampered` |
| Enroll new asset | `POST /v1/assets/enroll` |
| Verify asset integrity | `PUT /v1/assets/{id}/verify` |
| View alerts | `curl http://localhost:3000/v1/alerts` |
| Prometheus metrics | `curl http://localhost:3000/metrics` |

## Monitoring

- **Grafana:** http://localhost:3001 (admin/dfim_grafana_2026)
- **Prometheus:** http://localhost:9090
- **API logs:** /var/log/dfim/dfim-api.log
- **Audit trail:** /var/log/dfim/audit.jsonl

## Troubleshooting

| Problem | Check |
|---------|-------|
| API not responding | `systemctl status dfim-management-api` |
| DB connection errors | `pg_isready` |
| Auth failures | Verify DFIM_JWT_SECRET is set |
| Slow queries | `psql dfim_production -c "SELECT * FROM pg_stat_activity;"` |
| Rate limiting | Check logs for 429 responses |

## Backup & Recovery

```bash
# Manual backup
su -l postgres -c '/usr/local/bin/dfim-backup.sh'

# Restore
gunzip -c /var/backups/dfim/dfim_20260101_0200.sql.gz | psql dfim_production

# List backups
ls -la /var/backups/dfim/
```

## Security

- All API endpoints require JWT token (except /health, /metrics, /v1/auth/login)
- Rate limiting: 1000 req/s per IP
- Audit logs: /var/log/dfim/audit.jsonl
- TLS cert: /etc/dfim/tls/cert.pem

## SLA Targets

| Metric | Target |
|--------|--------|
| API uptime | 99.9% |
| P99 latency | <100ms |
| Integrity verification | <1ms P50 |
| Alert generation | <100ms after tamper detection |
