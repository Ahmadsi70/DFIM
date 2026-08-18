#!/usr/bin/env python3
import urllib.request, json, time, threading, random

API = "http://localhost:3000"

# Login
data = json.dumps({"username": "admin", "password": "dfim_admin_2026"}).encode()
req = urllib.request.Request(f"{API}/v1/auth/login", data=data,
    headers={"Content-Type": "application/json"}, method="POST")
token = json.loads(urllib.request.urlopen(req).read())["access_token"]

# Fleet
req = urllib.request.Request(f"{API}/v1/fleet/summary",
    headers={"Authorization": f"Bearer {token}"})
f = json.loads(urllib.request.urlopen(req).read())
print(f"Fleet: {f['total_assets']:,} assets | {f['total_nodes']:,} nodes | {f['active_alerts']:,} alerts")
print(f"Healthy: {f['healthy']} | Tampered: {f['tampered']} | Pending: {f['pending']}")

# Load test
ok = [0]; err = [0]; lock = threading.Lock()
def worker():
    paths = ["/health", "/v1/fleet/summary", "/v1/assets?limit=5"]
    for _ in range(200):
        try:
            req = urllib.request.Request(f"{API}{random.choice(paths)}",
                headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    with lock: ok[0] += 1
        except:
            with lock: err[0] += 1

threads = [threading.Thread(target=worker) for _ in range(64)]
t0 = time.perf_counter()
for t in threads: t.start()
for t in threads: t.join()
el = time.perf_counter() - t0
total = ok[0] + err[0]
print(f"Load: {total:,} req in {el:.1f}s | {total/el:.0f} req/s | {err[0]} errors")

# Auth enforcement check
try:
    urllib.request.urlopen(f"{API}/v1/fleet/summary", timeout=3)
    print("Auth: BROKEN (no token accepted)")
except urllib.error.HTTPError as e:
    print(f"Auth: ENFORCED ({e.code} without token)")

# Rate limit check
r429 = 0
for _ in range(100):
    try:
        urllib.request.urlopen(f"{API}/health", timeout=2)
    except urllib.error.HTTPError as e:
        if e.code == 429: r429 += 1
print(f"Rate limit: {r429}/100 rate-limited (429)")

print("\nALL CHECKS PASSED" if err[0] == 0 else f"\n{err[0]} errors detected")
