import subprocess
idxs = [
    'CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status)',
    'CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host_name)',
    'CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(asset_kind)',
    'CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_assets_verified ON assets(last_verified DESC)',
]
for idx in idxs:
    r = subprocess.run(['su', '-l', 'postgres', '-c', f'psql dfim_production -c "{idx}"'], capture_output=True, text=True, timeout=60)
    out = r.stdout.strip()[:80] if r.stdout else r.stderr.strip()[:80]
    print(out)
print("Indexes done")
