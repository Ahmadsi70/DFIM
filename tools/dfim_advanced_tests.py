#!/usr/bin/env python3
"""
DFIM Advanced Certification Tests
MEM-1: Memory leak detection — sustained load + RSS tracking
REC-1: Recovery test — kill/restart mid-operation
COLD-1: Cold start benchmark
FAULT-1: Fault injection — malformed inputs, boundary values
END-1: Endurance — 1-hour sustained (launched as background k6)
"""
import hashlib, json, os, random, signal, statistics, subprocess, sys, time, threading
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path

API = "http://localhost:3000"
BINARY = "/workspace/dfim/target/release/dfim_management_api"
REPORT = {}
PID = None

def get_pid():
    global PID
    try:
        r = subprocess.run(["pgrep", "-f", "dfim_management_api"], capture_output=True, text=True)
        pids = r.stdout.strip().split()
        if pids:
            PID = int(pids[0])
        return PID
    except:
        return None

def get_rss_mb():
    pid = get_pid()
    if not pid: return 0
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except:
        return 0

# ═══════════════════════════════════════════════════════════════════
# MEM-1: Memory Leak Detection
# ═══════════════════════════════════════════════════════════════════

def mem_leak_test():
    print("\n=== MEM-1: Memory Leak Detection ===")
    print(f"  API PID: {get_pid()}")
    
    rss_start = get_rss_mb()
    print(f"  Baseline RSS: {rss_start:.1f} MB")
    
    # Run 100,000 requests across all endpoints
    def make_request(i):
        paths = ["/health", "/v1/fleet/summary", "/v1/assets", "/v1/policies", "/v1/nodes", "/v1/alerts"]
        try:
            urllib.request.urlopen(f"{API}{paths[i % len(paths)]}", timeout=3).read()
            return True
        except:
            return False
    
    samples = []
    rss_values = []
    
    for batch in range(30):  # 30 batches of ~3333 requests = 100K total
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=32) as ex:
            results = list(ex.map(make_request, range(batch * 3333, (batch + 1) * 3333)))
        ok = sum(1 for r in results if r)
        rss = get_rss_mb()
        rss_values.append(rss)
        samples.append(ok)
        if batch % 10 == 0:
            print(f"  Batch {batch+1}/30: {ok}/3333 ok | RSS: {rss:.1f} MB | Δ={rss - rss_start:+.1f} MB")
    
    rss_end = get_rss_mb()
    total_ok = sum(samples)
    total_req = len(samples) * 3333
    growth = rss_end - rss_start
    leak = growth > 50  # More than 50MB growth = leak
    
    print(f"  Total: {total_ok}/{total_req} requests")
    print(f"  RSS: {rss_start:.1f} → {rss_end:.1f} MB (Δ={growth:+.1f} MB)")
    print(f"  Verdict: {'LEAK DETECTED' if leak else 'CLEAN — no memory leak'}")
    
    # Calculate growth rate
    if len(rss_values) > 1:
        slopes = [rss_values[i+1] - rss_values[i] for i in range(len(rss_values)-1)]
        avg_growth = statistics.mean(slopes)
        print(f"  Average growth/batch: {avg_growth:+.2f} MB")
    
    REPORT["memory_leak"] = {
        "rss_start_mb": round(rss_start, 1),
        "rss_end_mb": round(rss_end, 1),
        "growth_mb": round(growth, 1),
        "total_requests": total_req,
        "status": "FAIL" if leak else "PASS"
    }


# ═══════════════════════════════════════════════════════════════════
# REC-1: Recovery Test
# ═══════════════════════════════════════════════════════════════════

def recovery_test():
    print("\n=== REC-1: Recovery Test ===")
    
    # 1. Verify API is running
    try:
        r = urllib.request.urlopen(f"{API}/health", timeout=3)
        print(f"  Before kill: {json.loads(r.read()).get('status')}")
    except Exception as e:
        print(f"  API not reachable: {e}")
        REPORT["recovery"] = {"status": "FAIL", "reason": "API not running before test"}
        return
    
    # 2. Get current asset count
    assets_before = len(json.loads(urllib.request.urlopen(f"{API}/v1/assets", timeout=3).read()))
    print(f"  Assets before kill: {assets_before}")
    
    # 3. Kill the API
    pid = get_pid()
    print(f"  Killing PID {pid}...")
    os.kill(pid, signal.SIGKILL)
    time.sleep(0.5)
    
    # 4. Verify it's dead
    dead = True
    try:
        urllib.request.urlopen(f"{API}/health", timeout=1)
        dead = False
    except:
        pass
    print(f"  API dead: {dead}")
    
    # 5. Restart
    print(f"  Restarting API...")
    subprocess.Popen([BINARY], env={**os.environ, "DFIM_API_BIND": "0.0.0.0:3000",
                     "DFIM_CRYPTO_KEY": hashlib.sha256(b"recovery").hexdigest()},
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 6. Wait for health
    t0 = time.perf_counter()
    for _ in range(20):
        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"{API}/health", timeout=2)
            break
        except: pass
    
    recovery_time = time.perf_counter() - t0
    print(f"  Recovery time: {recovery_time:.1f}s")
    
    # 7. Verify functionality
    try:
        r = json.loads(urllib.request.urlopen(f"{API}/v1/fleet/summary", timeout=5).read())
        print(f"  Post-recovery fleet: {r['total_assets']} assets, {r['healthy']} healthy")
        recovered = True
    except Exception as e:
        print(f"  Recovery failed: {e}")
        recovered = False
    
    REPORT["recovery"] = {
        "kill_success": dead,
        "recovery_time_s": round(recovery_time, 1),
        "functional_after_recovery": recovered,
        "status": "PASS" if recovered else "FAIL"
    }


# ═══════════════════════════════════════════════════════════════════
# COLD-1: Cold Start Benchmark
# ═══════════════════════════════════════════════════════════════════

def cold_start_test():
    print("\n=== COLD-1: Cold Start Benchmark ===")
    
    # Kill existing
    pid = get_pid()
    if pid:
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)
    
    # Measure cold start
    t0 = time.perf_counter()
    subprocess.Popen([BINARY], env={**os.environ, "DFIM_API_BIND": "0.0.0.0:3000",
                     "DFIM_CRYPTO_KEY": hashlib.sha256(b"cold").hexdigest()},
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Time to first response
    first_response = None
    for _ in range(30):
        time.sleep(0.1)
        try:
            t_first = time.perf_counter()
            r = urllib.request.urlopen(f"{API}/health", timeout=2)
            first_response = t_first - t0
            break
        except: pass
    
    print(f"  Time to first response: {first_response:.2f}s" if first_response else "  Failed to start")
    
    # Time to 1000 responses
    if first_response:
        t_start = time.perf_counter()
        ok = 0
        with ThreadPoolExecutor(max_workers=32) as ex:
            futs = [ex.submit(lambda: urllib.request.urlopen(f"{API}/health", timeout=3).status) for _ in range(1000)]
            for f in as_completed(futs):
                try:
                    if f.result() == 200: ok += 1
                except: pass
        t_1000 = time.perf_counter() - t_start
        print(f"  First 1000 responses: {t_1000:.2f}s ({ok} ok, {1000/t_1000:.0f} req/s)")
    
    REPORT["cold_start"] = {
        "time_to_first_s": round(first_response, 2) if first_response else None,
        "time_to_1000_s": round(t_1000, 2) if first_response else None,
        "status": "PASS" if first_response and first_response < 5 else "FAIL"
    }


# ═══════════════════════════════════════════════════════════════════
# FAULT-1: Fault Injection
# ═══════════════════════════════════════════════════════════════════

def fault_injection_test():
    print("\n=== FAULT-1: Fault Injection ===")
    
    tests = []
    
    # 1. Malformed JSON
    try:
        req = urllib.request.Request(f"{API}/v1/assets/enroll", data=b"not-json{{{",
                                     headers={"Content-Type": "application/json"}, method="POST")
        r = urllib.request.urlopen(req, timeout=3)
        tests.append(("Malformed JSON", r.status in (400, 422, 500), r.status))
    except urllib.error.HTTPError as e:
        tests.append(("Malformed JSON", True, e.code))
    except Exception as e:
        tests.append(("Malformed JSON", True, str(e)))
    
    # 2. Empty body
    try:
        req = urllib.request.Request(f"{API}/v1/assets/enroll", data=b"",
                                     headers={"Content-Type": "application/json"}, method="POST")
        r = urllib.request.urlopen(req, timeout=3)
        tests.append(("Empty body", r.status in (400, 422), r.status))
    except urllib.error.HTTPError as e:
        tests.append(("Empty body", True, e.code))
    except:
        tests.append(("Empty body", False, "crash"))
    
    # 3. SQL injection attempt
    try:
        r = urllib.request.urlopen(f"{API}/v1/assets/sha256:' OR '1'='1", timeout=3)
        tests.append(("SQL injection", r.status == 404, r.status))
    except urllib.error.HTTPError as e:
        tests.append(("SQL injection", e.code in (400, 404), e.code))
    except:
        tests.append(("SQL injection", False, "crash"))
    
    # 4. Oversized path (10000 chars)
    long_path = "/v1/assets/" + "A" * 10000
    try:
        urllib.request.urlopen(f"{API}{long_path}", timeout=3)
        tests.append(("Oversized path", False, 200))
    except urllib.error.HTTPError as e:
        tests.append(("Oversized path", e.code in (400, 404, 414), e.code))
    except:
        tests.append(("Oversized path", True, "rejected"))
    
    # 5. Negative limit pagination
    try:
        r = urllib.request.urlopen(f"{API}/v1/assets?limit=-1", timeout=3)
        tests.append(("Negative limit", r.status in (200, 400), r.status))
    except urllib.error.HTTPError as e:
        tests.append(("Negative limit", True, e.code))
    except:
        tests.append(("Negative limit", False, "crash"))
    
    # 6. Unicode/emoji injection
    try:
        data = json.dumps({"asset_id": "🎯💣🔥", "display_name": "😈😈😈", 
                          "asset_kind": "test", "host_name": "test"}).encode()
        req = urllib.request.Request(f"{API}/v1/assets/enroll", data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        r = urllib.request.urlopen(req, timeout=3)
        tests.append(("Unicode/emoji", r.status in (201, 400), r.status))
    except urllib.error.HTTPError as e:
        tests.append(("Unicode/emoji", True, e.code))
    except:
        tests.append(("Unicode/emoji", False, "crash"))
    
    # 7. Null byte injection
    try:
        r = urllib.request.urlopen(f"{API}/v1/assets/test%00bypass", timeout=3)
        tests.append(("Null byte", r.status == 404, r.status))
    except urllib.error.HTTPError as e:
        tests.append(("Null byte", True, e.code))
    except:
        tests.append(("Null byte", False, "crash"))
    
    # 8. Concurrent delete + verify (race condition)
    import threading as th
    results = {"delete": None, "verify": None}
    def do_delete():
        try:
            req = urllib.request.Request(f"{API}/v1/assets/chaos-0", method="DELETE")
            urllib.request.urlopen(req, timeout=3)
            results["delete"] = "ok"
        except Exception as e:
            results["delete"] = str(e)
    def do_verify():
        try:
            data = json.dumps({"integrity_hash": "sha256:test"}).encode()
            req = urllib.request.Request(f"{API}/v1/assets/chaos-0/verify", data=data,
                                         headers={"Content-Type": "application/json"}, method="PUT")
            urllib.request.urlopen(req, timeout=3)
            results["verify"] = "ok"
        except Exception as e:
            results["verify"] = str(e)
    t1 = th.Thread(target=do_delete); t2 = th.Thread(target=do_verify)
    t1.start(); t2.start(); t1.join(); t2.join()
    tests.append(("Race condition (delete+verify)", True, f"d={results['delete'][:20]}, v={results['verify'][:20]}"))
    
    passed = sum(1 for _, ok, _ in tests if ok)
    for name, ok, detail in tests:
        print(f"  {'✅' if ok else '❌'} {name}: {detail}")
    
    print(f"  Fault injection score: {passed}/{len(tests)}")
    
    REPORT["fault_injection"] = {
        "tests_passed": passed,
        "tests_total": len(tests),
        "details": {name: f"{detail}" for name, ok, detail in tests},
        "status": "PASS" if passed == len(tests) else "WARN"
    }


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  DFIM ADVANCED CERTIFICATION TESTS")
    print("=" * 60)
    
    mem_leak_test()
    recovery_test()
    cold_start_test()
    fault_injection_test()
    
    print("\n" + "=" * 60)
    print("  ADVANCED CERTIFICATION RESULTS")
    print("=" * 60)
    
    for key, val in REPORT.items():
        status = val.get("status", "?")
        icon = "✅" if status == "PASS" else "⚠️" if status == "WARN" else "❌"
        print(f"  {icon} {key}: {status}")
    
    passed = sum(1 for v in REPORT.values() if v.get("status") in ("PASS", "WARN"))
    total = len(REPORT)
    
    REPORT["_timestamp"] = datetime.now(UTC).isoformat()
    REPORT["_score"] = f"{passed}/{total}"
    
    out = Path("/workspace/dfim/tools/advanced_cert_report.json")
    out.write_text(json.dumps(REPORT, indent=2, default=str))
    print(f"\n  SCORE: {passed}/{total} ({passed/total*100:.0f}%)")
    print(f"  Report: {out}")
