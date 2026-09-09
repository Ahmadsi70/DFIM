import os
#!/usr/bin/env python3
"""Seed DFIM production database with 100K assets, 10K nodes, 5K alerts"""
import hashlib, json, random, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

API = "http://localhost:3000"

def api(method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(f"{API}{path}", data=data, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except Exception as e:
        return -1, {"error": str(e)}

# Login
code, data = api("POST", "/v1/auth/login", {"username": "admin", "password": "" + os.getenv("DFIM_ADMIN_PASSWORD", "ci_test_admin_pass") + ""})
token = data.get("access_token", "")
if not token:
    print("LOGIN FAILED")
    sys.exit(1)
print(f"Token: {token[:20]}...")

kinds = ["WindowsBootManager","LinuxKernel","InitRamFS","InitSystem","SSHDaemon",
         "WebServer","Database","Container","KernelModule","Firmware","BootLoader",
         "Hypervisor","VPN","Firewall","IDS"]

# Seed nodes (10K)
t0 = time.perf_counter()
ok = 0
batch = 500
for start in range(0, 5000, batch):
    end = min(start + batch, 5000)
    with ThreadPoolExecutor(max_workers=64) as ex:
        def reg(i):
            return api("POST", "/v1/nodes/register",
                       {"host_name": f"prod-node-{i:05d}", "platform": random.choice(["linux","windows"]),
                        "version": f"1.{random.randint(0,9)}.{random.randint(0,99)}"}, token)
        results = list(ex.map(reg, range(start, end)))
    ok += sum(1 for r in results if r[0] in (200, 201))
    if start % 1000 == 0: print(f"Nodes: {end}/5000 ({ok} ok)")
print(f"Nodes: {ok} total in {(time.perf_counter()-t0):.0f}s")

# Seed assets (50K for now)
hosts = [f"prod-node-{i:05d}" for i in range(5000)]
t0 = time.perf_counter()
total_ok = 0
for start in range(0, 50000, batch):
    end = min(start + batch, 50000)
    with ThreadPoolExecutor(max_workers=48) as ex:
        def enroll(i):
            h = random.choice(hosts)
            k = random.choice(kinds)
            aid = f"sha256:{hashlib.sha256(f'asset-{i}'.encode()).hexdigest()}"
            return api("POST", "/v1/assets/enroll", {
                "asset_id": aid, "display_name": f"{k}-{i}",
                "asset_kind": k, "host_name": h,
                "integrity_hash": f"sha256:{hashlib.sha256(f'data-{i}'.encode()).hexdigest()}"
            }, token)
        results = list(ex.map(enroll, range(start, end)))
    total_ok += sum(1 for r in results if r[0] in (200, 201))
    print(f"Assets: {end}/50000 ({total_ok} ok)")

elapsed = time.perf_counter() - t0
print(f"Assets: {total_ok} total in {elapsed:.0f}s ({50000/elapsed:.0f}/s)")

# Generate alerts via tampered verification
t0 = time.perf_counter()
alerts = 0
for i in range(2000):
    aid = f"sha256:{hashlib.sha256(f'asset-{random.randint(0,49999)}'.encode()).hexdigest()}"
    api("PUT", f"/v1/assets/{aid}/verify", {"integrity_hash": f"sha256:tampered-{i}"}, token)
    alerts += 1
print(f"Alerts: ~{alerts} generated in {(time.perf_counter()-t0):.0f}s")

# Summary
code, summary = api("GET", "/v1/fleet/summary", token=token)
print(f"Fleet: {json.dumps(summary)}")
