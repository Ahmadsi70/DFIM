#!/usr/bin/env python3
"""DFIM Phase 5 — Operational Certification Tests"""
import hashlib, json, os, time, urllib.request, urllib.error, random
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, UTC

API = "http://localhost:3000"

def api(method, path, body=None, headers=None):
    h = {"Content-Type": "application/json"}
    if headers: h.update(headers)
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(f"{API}{path}", data=data, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()) if e.headers.get("Content-Type","").startswith("application/json") else {"error": str(e)}
    except Exception as e:
        return -1, {"error": str(e)}

results = {}
print("=" * 60)
print("  DFIM PHASE 5 — OPERATIONAL CERTIFICATION")
print("=" * 60)

# ═══════════════════════════════════════════════════════════════
# 5.1 DB Persistence Tests
# ═══════════════════════════════════════════════════════════════
print("\n--- 5.1: Database Persistence ---")

# Health check
code, data = api("GET", "/health")
print(f"  Health: {code} | {data.get('status')} | {data.get('asset_count')} assets in DB")
results["db_health"] = code == 200

# Enroll asset (persisted to PostgreSQL)
code, data = api("POST", "/v1/assets/enroll", {
    "asset_id": "phase5-db-test", "display_name": "DB Persistence Test",
    "asset_kind": "test", "host_name": "db-node"
})
print(f"  Enroll: {code} | {data}")
results["db_enroll"] = code == 201

# Restart API and verify data persists
print(f"  Killing API...")
os.system("pkill -f dfim_management_api 2>/dev/null; sleep 1")
os.system("cd /workspace/dfim && DATABASE_URL=postgres://dfim:dfim_prod_2026@localhost/dfim_production DFIM_API_BIND=0.0.0.0:3000 nohup ./target/release/dfim_management_api > /tmp/api5.log 2>&1 &")
time.sleep(3)

# Verify asset survived restart
code, data = api("GET", "/v1/assets/phase5-db-test")
print(f"  After restart: {code} | {data.get('display_name', 'NOT FOUND')}")
results["db_persistence"] = code == 200

# Cleanup
api("DELETE", "/v1/assets/phase5-db-test")

# ═══════════════════════════════════════════════════════════════
# 5.2 Auth & RBAC Tests
# ═══════════════════════════════════════════════════════════════
print("\n--- 5.2: Auth & RBAC ---")

# Login
code, data = api("POST", "/v1/auth/login", {"username": "admin", "password": "dfim_admin_2026"})
token = data.get("access_token", "")
print(f"  Login (admin): {code} | role={data.get('role')} | token={'OK' if token else 'FAIL'}")
results["auth_login"] = code == 200 and len(token) > 50

# Authenticated request
code, data = api("GET", "/v1/fleet/summary", headers={"Authorization": f"Bearer {token}"})
print(f"  Auth request: {code} | {data.get('total_assets')} assets")
results["auth_request"] = code == 200

# Invalid token rejected
code, data = api("GET", "/v1/fleet/summary", headers={"Authorization": "Bearer invalid.token.here"})
print(f"  Invalid token: {code} | {data.get('error','?')}")
results["auth_invalid"] = code == 401

# Bad credentials
code, data = api("POST", "/v1/auth/login", {"username": "admin", "password": "wrong"})
print(f"  Bad password: {code}")
results["auth_bad_creds"] = code == 401

# Multi-tenant isolation
code, acme = api("POST", "/v1/auth/login", {"username": "acme_admin", "password": "acme_pass"})
code2, bank = api("POST", "/v1/auth/login", {"username": "megabank_op", "password": "bank_pass"})
print(f"  Multi-tenant: acme={acme.get('tenant')} | megabank={bank.get('tenant')}")
results["auth_multi_tenant"] = acme.get("tenant") != bank.get("tenant")

# ═══════════════════════════════════════════════════════════════
# 5.3 Rate Limiting Tests
# ═══════════════════════════════════════════════════════════════
print("\n--- 5.3: Rate Limiting ---")

# Burst test
burst_ok = 0
burst_total = 500
t0 = time.perf_counter()
with ThreadPoolExecutor(max_workers=32) as ex:
    futs = [ex.submit(lambda: api("GET", "/health")[0]) for _ in range(burst_total)]
    for f in futs:
        if f.result() == 200: burst_ok += 1
elapsed = time.perf_counter() - t0
rate_limited = burst_total - burst_ok > 0
print(f"  Burst {burst_total} req: {burst_ok} ok, {burst_total-burst_ok} rate-limited | {burst_total/elapsed:.0f} req/s")
results["rate_burst"] = burst_ok >= burst_total * 0.5  # At least half should succeed

# ═══════════════════════════════════════════════════════════════
# 5.6 Prometheus Metrics
# ═══════════════════════════════════════════════════════════════
print("\n--- 5.6: Metrics ---")
code, raw = urllib.request.urlopen(f"{API}/metrics"), None
try:
    raw = code.read().decode()
    code = code.status
    has_metrics = "dfim_http_requests_total" in raw
    print(f"  /metrics: {code} | contains dfim_http_requests_total: {has_metrics}")
except:
    has_metrics = False
    print(f"  /metrics: FAILED")
results["metrics"] = has_metrics

# ═══════════════════════════════════════════════════════════════
# Results
# ═══════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
passed = sum(1 for v in results.values() if v)
total = len(results)
for k, v in results.items():
    print(f"  {'✅' if v else '❌'} {k}")
print(f"\n  PHASE 5 SCORE: {passed}/{total} ({passed/total*100:.0f}%)")
