#!/usr/bin/env python3
"""DFIM Management API — integration & load test."""
import json, time, statistics, requests, concurrent.futures, sys

API = "http://localhost:3000"
OK, FAIL = 0, 0
TIMINGS = []

def call(method, path, data=None):
    global OK, FAIL
    t0 = time.perf_counter()
    try:
        if method == "GET": r = requests.get(f"{API}{path}", timeout=5)
        elif method == "POST": r = requests.post(f"{API}{path}", json=data, timeout=5)
        elif method == "PUT": r = requests.put(f"{API}{path}", json=data, timeout=5)
        elif method == "DELETE": r = requests.delete(f"{API}{path}", timeout=5)
        else: return None
        el = (time.perf_counter() - t0) * 1000
        TIMINGS.append(el)
        if r.status_code < 400: OK += 1
        else: FAIL += 1
        return r
    except Exception as e:
        FAIL += 1
        TIMINGS.append(9999)
        return None

print("=== DFIM Management API — Integration Test ===")
print()

# 1. Health
r = call("GET", "/health")
print(f"[HEALTH] {r.status_code} | {r.json()['status']} | {r.json()['asset_count']} assets")

# 2. Fleet summary
r = call("GET", "/v1/fleet/summary")
d = r.json()
print(f"[FLEET]  {d['total_assets']} total | {d['healthy']} healthy | {d['tampered']} tampered | {d['integrity_coverage_pct']:.0f}% coverage")

# 3. List assets
r = call("GET", "/v1/assets")
print(f"[ASSETS] {len(r.json())} enrolled")

# 4. Enroll new asset
r = call("POST", "/v1/assets/enroll", {"asset_id":"bench-nginx-v2","display_name":"nginx","asset_kind":"WebServer","host_name":"node-05","integrity_hash":"sha256:known-good"})
print(f"[ENROLL] {r.status_code} – {r.json().get('asset_id','?')}")

# 5. Verify with correct hash -> healthy
r = call("PUT", "/v1/assets/bench-nginx-v2/verify", {"integrity_hash":"sha256:known-good"})
print(f"[VERIFY-OK] status={r.json()['status']}")

# 6. Verify with wrong hash -> tampered + alert
r = call("PUT", "/v1/assets/bench-nginx-v2/verify", {"integrity_hash":"sha256:tampered"})
print(f"[VERIFY-FAIL] status={r.json()['status']}")

# 7. Check alerts
r = call("GET", "/v1/alerts")
alerts = r.json()
print(f"[ALERTS] {len(alerts)} alerts | latest: {alerts[0]['message'][:50] if alerts else 'none'}")

# 8. Acknowledge alert
if alerts:
    r = call("POST", f"/v1/alerts/{alerts[0]['alert_id']}/acknowledge")
    print(f"[ACK] {r.json()['acknowledged']}")

# 9. Register nodes
for i in range(5):
    r = call("POST", "/v1/nodes/register", {"host_name":f"edge-{i}","platform":"linux","version":"0.1.0"})
print(f"[NODES] {len(call('GET', '/v1/nodes').json())} registered")

# 10. Get OpenAPI spec
r = call("GET", "/openapi.json")
spec = r.json()
print(f"[OPENAPI] {spec['info']['title']} | {len(spec['paths'])} paths")

# 11. Load test — concurrent requests
print()
print("=== LOAD TEST (100 concurrent requests) ===")
LOAD_TIMINGS = []
OK2 = 0

def load_worker(_):
    t0 = time.perf_counter()
    try:
        r = requests.get(f"{API}/health", timeout=5)
        el = (time.perf_counter() - t0) * 1000
        return (el, r.status_code == 200)
    except:
        return (9999, False)

with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
    results = list(ex.map(load_worker, range(100)))

LOAD_TIMINGS = [r[0] for r in results]
OK2 = sum(1 for r in results if r[1])
sorted_t = sorted(LOAD_TIMINGS)
p50 = statistics.median(sorted_t)
p99 = sorted_t[int(len(sorted_t) * 0.99)]
p999 = sorted_t[int(len(sorted_t) * 0.999)]

print(f"Total: {len(LOAD_TIMINGS)} | OK: {OK2} | FAIL: {len(LOAD_TIMINGS)-OK2}")
print(f"P50: {p50:.2f}ms | P99: {p99:.2f}ms | P99.9: {p999:.2f}ms")
print(f"Mean: {statistics.mean(LOAD_TIMINGS):.2f}ms | Throughput: {1000/p50:.0f} req/s")
print()

# 12. Delete asset
r = call("DELETE", "/v1/assets/bench-nginx-v2")
print(f"[DELETE] {r.status_code} – {r.json()}")

print()
print(f"=== RESULTS: {OK}/{OK+FAIL} PASSED ===")
sys.exit(0 if FAIL == 0 else 1)
