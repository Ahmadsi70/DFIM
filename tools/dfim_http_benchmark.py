#!/usr/bin/env python3
"""DFIM API real HTTP benchmark."""
import time, statistics, concurrent.futures, urllib.request, json

API = "http://localhost:3000"
ITER = 1000

def hit(path):
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(API + path, timeout=5) as r:
            r.read()
        return (time.perf_counter() - t0) * 1000
    except:
        return None

# Sequential
times = []
for _ in range(100):
    t = hit("/health")
    if t: times.append(t)
s = sorted(times)
print(f"[SEQ]  n={len(times)} | P50={statistics.median(s):.2f}ms | P99={s[int(len(s)*0.99)]:.2f}ms | Mean={statistics.mean(s):.2f}ms | {1000/statistics.median(s):.0f} req/s")

# C16
times2 = []
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
    t0 = time.perf_counter()
    futs = [ex.submit(hit, "/health") for _ in range(ITER)]
    for f in concurrent.futures.as_completed(futs):
        r = f.result()
        if r: times2.append(r)
total_ms = (time.perf_counter() - t0) * 1000
s2 = sorted(times2)
print(f"[C16]  n={len(times2)} | P50={statistics.median(s2):.2f}ms | P99={s2[int(len(s2)*0.99)]:.2f}ms | Mean={statistics.mean(s2):.2f}ms | {ITER/(total_ms/1000):.0f} req/s")

# C64
times3 = []
with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
    t0 = time.perf_counter()
    futs = [ex.submit(hit, "/health") for _ in range(ITER)]
    for f in concurrent.futures.as_completed(futs):
        r = f.result()
        if r: times3.append(r)
total_ms = (time.perf_counter() - t0) * 1000
s3 = sorted(times3)
print(f"[C64]  n={len(times3)} | P50={statistics.median(s3):.2f}ms | P99={s3[int(len(s3)*0.99)]:.2f}ms | Mean={statistics.mean(s3):.2f}ms | {ITER/(total_ms/1000):.0f} req/s")

# Fleet summary benchmark
for _ in range(10):
    hit("/v1/fleet/summary")
t0 = time.perf_counter()
for _ in range(100):
    hit("/v1/fleet/summary")
el = (time.perf_counter() - t0) * 1000
print(f"[FLEET] 100 req in {el:.0f}ms | {100000/el:.0f} req/s")

# Asset enrollment benchmark
t0 = time.perf_counter()
for i in range(50):
    rid = f"bench-{i}"
    import json as j
    t = time.perf_counter()
    req = urllib.request.Request(f"{API}/v1/assets/enroll",
        data=j.dumps({"asset_id":rid,"display_name":f"Bench Asset {i}","asset_kind":"Benchmark","host_name":"bench-node"}).encode(),
        headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read()
    except:
        pass
el2 = (time.perf_counter() - t0) * 1000
print(f"[ENROLL] 50 assets in {el2:.0f}ms | {el2/50:.1f}ms/asset")

# Cleanup
for i in range(50):
    req = urllib.request.Request(f"{API}/v1/assets/bench-{i}", method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read()
    except:
        pass

print("\n=== REAL HTTP BENCHMARK COMPLETE ===")
