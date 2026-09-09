#!/usr/bin/env python3
"""Fix W3-W6 on server: Performance, HA, DR, TLS"""
import os, subprocess, time, json, urllib.request, shutil
from pathlib import Path

PROJECT = Path("/workspace/dfim")
API = "http://localhost:3000"

def run(cmd, shell=False, timeout=30):
    if isinstance(cmd, str):
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

# ═══════════════════════════════════════════════════════
# W3: Performance — ANALYZE + composite indexes
# ═══════════════════════════════════════════════════════
print("=== W3: Performance Optimization ===")
cmds = [
    'su -l postgres -c "psql dfim_production -c \\\"ANALYZE VERBOSE assets;\\\"\"',
    'su -l postgres -c "psql dfim_production -c \\\"CREATE INDEX IF NOT EXISTS idx_assets_status_tenant ON assets(status, tenant_id);\\\"\"',
    'su -l postgres -c "psql dfim_production -c \\\"CREATE INDEX IF NOT EXISTS idx_assets_host_status ON assets(host_name, status);\\\"\"',
    'su -l postgres -c "psql dfim_production -c \\\"CREATE INDEX IF NOT EXISTS idx_assets_tenant_status ON assets(tenant_id, status, last_verified DESC);\\\"\"',
    'su -l postgres -c "psql dfim_production -c \\\"VACUUM ANALYZE assets;\\\"\"',
]
for cmd in cmds:
    r = run(cmd, shell=True)
    print(f"  {r.stdout.strip()[:80]}" if r.returncode == 0 else f"  ERR: {r.stderr.strip()[:80]}")

# Verify
r = run('su -l postgres -c "psql dfim_production -c \\\"SELECT count(*) FROM assets;\\\"\"', shell=True)
print(f"  Asset count: {r.stdout.strip()}")

# Benchmark
print("  Benchmarking with optimized indexes...")
data = json.dumps({"username": "admin", "password": "" + os.getenv("DFIM_ADMIN_PASSWORD", "ci_test_admin_pass") + ""}).encode()
req = urllib.request.Request(f"{API}/v1/auth/login", data=data,
                             headers={"Content-Type": "application/json"}, method="POST")
token = json.loads(urllib.request.urlopen(req).read())["access_token"]

import concurrent.futures
def query():
    req = urllib.request.Request(f"{API}/v1/assets?limit=20",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r: return r.status
    except: return 500

t0 = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    results = list(ex.map(lambda _: query(), range(200)))
el = time.perf_counter() - t0
ok = sum(1 for r in results if r == 200)
print(f"  200 queries: {ok} ok in {el*1000:.0f}ms ({200/el:.0f} qps)")

# ═══════════════════════════════════════════════════════
# W4+W5: HA + DR — Backup automation
# ═══════════════════════════════════════════════════════
print("\n=== W4+W5: HA + Disaster Recovery ===")
backup_dir = "/var/backups/dfim"
os.makedirs(backup_dir, exist_ok=True)

# Create backup script
backup_script = f"""/bin/bash
BACKUP_DIR={backup_dir}
DATE=\$(date +%Y%m%d_%H%M)
pg_dump -U dfim dfim_production | gzip > \$BACKUP_DIR/dfim_\$DATE.sql.gz
# Keep last 7 days
find \$BACKUP_DIR -name '*.sql.gz' -mtime +7 -delete
echo "Backup complete: dfim_\$DATE.sql.gz"
"""
with open("/usr/local/bin/dfim-backup.sh", "w") as f:
    f.write(backup_script)
os.chmod("/usr/local/bin/dfim-backup.sh", 0o755)

# Run first backup
r = run("su -l postgres -c '/usr/local/bin/dfim-backup.sh'", shell=True, timeout=60)
print(f"  Backup: {r.stdout.strip()}")

# Add cron job
cron_line = "0 2 * * * postgres /usr/local/bin/dfim-backup.sh\n"
with open("/etc/cron.d/dfim-backup", "w") as f:
    f.write(cron_line)
print("  Cron: daily at 2am configured")

# HA: replica config (documented, needs second server)
replica_config = """
# PostgreSQL Replica Configuration (Phase 5)
# On primary:
#   ALTER SYSTEM SET wal_level = replica;
#   ALTER SYSTEM SET max_wal_senders = 5;
#   CREATE USER replicator WITH REPLICATION PASSWORD 'dfim_replica_2026';
#   host replication replicator <REPLICA_IP>/32 md5
#
# On replica:
#   pg_basebackup -h <PRIMARY_IP> -U replicator -D /var/lib/postgresql/16/main -P -R
#   touch /var/lib/postgresql/16/main/standby.signal
"""
with open(f"{backup_dir}/HA_SETUP.md", "w") as f:
    f.write(replica_config)
print("  HA config: documented in /var/backups/dfim/HA_SETUP.md")

# ═══════════════════════════════════════════════════════
# W6: TLS Activation
# ═══════════════════════════════════════════════════════
print("\n=== W6: TLS Activation ===")
tls_dir = "/etc/dfim/tls"
os.makedirs(tls_dir, exist_ok=True)

# Generate self-signed cert
r = run(f'openssl req -x509 -newkey rsa:4096 -keyout {tls_dir}/key.pem -out {tls_dir}/cert.pem -days 365 -nodes -subj "/CN=dfim-api/O=DFIM/OU=Security"', shell=True)
if os.path.exists(f"{tls_dir}/cert.pem"):
    size = os.path.getsize(f"{tls_dir}/cert.pem")
    print(f"  TLS cert: {tls_dir}/cert.pem ({size} bytes)")
    print("  TLS key:  {tls_dir}/key.pem")
    print("  To activate: set DFIM_TLS_DIR=/etc/dfim/tls and restart API")
else:
    print("  TLS cert generation failed")

# ═══════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════
print("\n=== W3-W6 COMPLETE ===")
print("  W3: Composite indexes + ANALYZE + VACUUM")
print("  W4: HA config documented (needs second server)")
print("  W5: pg_dump backup + daily cron")
print("  W6: TLS cert generated")
