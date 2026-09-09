import os
#!/usr/bin/env python3
"""DFIM Ultimate Stress — Fast version, 5 tests, 10 min total"""
import hashlib, json, os, random, signal, statistics, subprocess, sys, time, threading
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import Counter

API = "http://localhost:3000"
PROJECT = Path("/workspace/dfim")
REPORT = {}
TOKEN = None
LOCK = threading.Lock()
ERRORS = [0]

def api(method, path, body=None):
    h = {"Content-Type": "application/json"}
    if TOKEN: h["Authorization"] = f"Bearer {TOKEN}"
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(f"{API}{path}", data=data, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try: b = json.loads(e.read())
        except: b = {}
        return e.code, b
    except Exception as e:
        with LOCK: ERRORS[0] += 1
        return -1, {}

def login(): 
    global TOKEN
    TOKEN = api("POST", "/v1/auth/login", {"username":"admin","password":"" + os.getenv("DFIM_ADMIN_PASSWORD", "ci_test_admin_pass") + ""})[1].get("access_token","")
    return bool(TOKEN)

# ═══════════════════════════════════════════════════════════════
# T1: 50K requests in 2 minutes
# ═══════════════════════════════════════════════════════════════
def t1_load():
    print("\n=== T1: 50K REQUESTS IN 120s ===")
    ok = [0]; lat = []
    def w():
        for _ in range(520):
            t0 = time.perf_counter_ns()
            code, _ = api("GET", random.choice(["/health","/v1/fleet/summary","/v1/assets?limit=5"]))
            el = (time.perf_counter_ns()-t0)/1e6
            with LOCK: lat.append(el); ok[0] += 1 if code==200 else 0
    
    threads = [threading.Thread(target=w) for _ in range(96)]
    t0 = time.perf_counter()
    for t in threads: t.start()
    for _ in range(12):
        time.sleep(10)
        print(f"  {ok[0]} requests | {len(lat)} lat samples")
    for t in threads: t.join()
    el = time.perf_counter()-t0
    p = statistics.median(lat) if lat else 0
    print(f"  {ok[0]} ok / {len(lat)} total | {len(lat)/el:.0f} req/s | P50={p:.1f}ms")
    REPORT["load_50k"] = {"rps": round(len(lat)/el), "p50": round(p,1), "errors": ERRORS[0], "status": "PASS" if ok[0]>40000 else "WARN"}

# ═══════════════════════════════════════════════════════════════
# T2: All attacks in parallel
# ═══════════════════════════════════════════════════════════════
def t2_attacks():
    print("\n=== T2: ALL ATTACKS IN PARALLEL ===")
    res = {"brute_cracked":0, "exfil":0, "rate_lim":0, "malformed":0}
    lk = threading.Lock()
    
    def brute():
        crackers = ["password","123456","admin","dfim","changeme","qwerty","letmein","DFIM2026","passw0rd","secret"]
        cracked, rl = 0, 0
        for pw in (crackers * 300)[:3000]:
            code, _ = api("POST", "/v1/auth/login", {"username":"admin","password":pw})
            if code==200: cracked+=1
            elif code==429: rl+=1
        with lk: res["brute_cracked"]=cracked; res["rate_lim"]=rl
    
    def exfil():
        count = 0
        for off in range(0, 5000, 100):
            code, data = api("GET", f"/v1/assets?limit=100&offset={off}")
            if code==200: count += len(data) if isinstance(data,list) else 0
        with lk: res["exfil"] = count
    
    def malform():
        ok = 0
        payloads = [b"not json", b"{"*100, b"\x00"*100, b"<script>alert(1)</script>"]
        for _ in range(500):
            try:
                req = urllib.request.Request(f"{API}/v1/assets/enroll", data=random.choice(payloads),
                    headers={"Content-Type":"application/json"}, method="POST")
                urllib.request.urlopen(req, timeout=5)
            except: ok += 1
        with lk: res["malformed"] = ok
    
    def race():
        for i in range(20):
            aid = f"race-para-{i}"
            api("POST","/v1/assets/enroll",{"asset_id":aid,"display_name":f"R{i}","asset_kind":"test","host_name":"race"})
            t1=threading.Thread(target=lambda: api("DELETE",f"/v1/assets/{aid}"))
            t2=threading.Thread(target=lambda: api("PUT",f"/v1/assets/{aid}/verify",{"integrity_hash":"sha256:test"}))
            t1.start();t2.start();t1.join();t2.join()
    
    threads = [threading.Thread(target=f) for f in [brute, exfil, malform, race]]
    t0 = time.perf_counter()
    for t in threads: t.start()
    for t in threads: t.join()
    el = time.perf_counter()-t0
    
    code, _ = api("GET", "/health")
    print(f"  Duration: {el:.0f}s | Brute cracked: {res['brute_cracked']} | Rate-limited: {res['rate_lim']} | Exfiltrated: {res['exfil']} | Malformed handled: {res['malformed']} | API: {'ALIVE' if code==200 else 'DEAD'}")
    REPORT["attacks"] = {"brute_cracked":res['brute_cracked'],"rate_limited":res['rate_lim'],"exfiltrated":res['exfil'],"api_alive":code==200,"status":"PASS" if code==200 and res['brute_cracked']==0 else "FAIL"}

# ═══════════════════════════════════════════════════════════════
# T3: DB crash recovery
# ═══════════════════════════════════════════════════════════════
def t3_db_crash():
    print("\n=== T3: DB CRASH RECOVERY ===")
    code, before = api("GET", "/v1/fleet/summary")
    assets_before = before.get("total_assets", 0)
    print(f"  Assets before: {assets_before}")
    
    api("POST", "/v1/assets/enroll", {"asset_id":"crash-test-final","display_name":"CrashTest","asset_kind":"test","host_name":"crash"})
    
    t0 = time.perf_counter()
    print("  Killing PostgreSQL...")
    subprocess.run(["pkill","-9","-f","postgres"], capture_output=True)
    time.sleep(2)
    subprocess.run(["pg_ctlcluster","16","main","start"], capture_output=True, timeout=30)
    time.sleep(3)
    
    subprocess.run(["pkill","-f","dfim_management_api"], capture_output=True)
    time.sleep(1)
    
    env = os.environ.copy()
    env["DATABASE_URL"] = "postgres://dfim:" + os.getenv("DFIM_DB_PASSWORD", "ci_test_password") + "@localhost/dfim_production"
    env["DFIM_JWT_SECRET"] = "prod-jwt-ultimate-v2"
    env["DFIM_API_BIND"] = "0.0.0.0:3000"
    env["PATH"] = "/root/.cargo/bin:" + env.get("PATH", "")
    subprocess.Popen([str(PROJECT / "target/release/dfim_management_api")], env=env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for _ in range(15):
        time.sleep(1)
        if login(): break
    
    recovery = time.perf_counter() - t0
    code, after = api("GET", "/v1/fleet/summary")
    intact = after.get("total_assets",0) >= assets_before
    print(f"  Recovery: {recovery:.1f}s | Assets after: {after.get('total_assets',0)} | {'INTACT ✅' if intact else 'LOST ❌'}")
    REPORT["db_crash"] = {"recovery_s": round(recovery,1), "intact": intact, "status": "PASS" if intact else "FAIL"}

# ═══════════════════════════════════════════════════════════════
# T4: Memory stability
# ═══════════════════════════════════════════════════════════════
def t4_memory():
    print("\n=== T4: MEMORY STABILITY ===")
    r = subprocess.run(["pgrep","-f","dfim_management_api"], capture_output=True, text=True)
    pid = int(r.stdout.strip().split()[0]) if r.stdout.strip() else None
    if not pid: REPORT["memory"]={"status":"SKIP"}; return
    
    def rss():
        try:
            with open(f"/proc/{pid}/status") as f:
                for l in f:
                    if "VmRSS:" in l: return int(l.split()[1])/1024
        except: return 0
    
    rss0 = rss()
    print(f"  Starting RSS: {rss0:.1f} MB")
    
    ok = [0]
    def w():
        for _ in range(400):
            code, _ = api("GET", "/v1/fleet/summary")
            if code==200: ok[0]+=1
    
    threads = [threading.Thread(target=w) for _ in range(24)]
    for t in threads: t.start()
    
    samples = [rss0]
    for i in range(6):
        time.sleep(20)
        samples.append(rss())
        print(f"  Minute {(i+1)/3:.0f}: RSS={samples[-1]:.1f}MB | {ok[0]} reqs")
    
    for t in threads: t.join()
    rss_end = rss()
    growth = rss_end - rss0
    print(f"  Final RSS: {rss_end:.1f}MB (delta={growth:+.1f}MB) | {'STABLE ✅' if growth<50 else 'LEAK ❌'}")
    REPORT["memory"] = {"rss0":rss0,"rss_end":rss_end,"delta":round(growth,1),"status":"PASS" if growth<50 else "FAIL"}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    login()
    print(f"Auth: {'OK' if TOKEN else 'FAIL'}")
    code, f = api("GET", "/v1/fleet/summary")
    print(f"Fleet: {f.get('total_assets','?')} assets | {f.get('total_nodes','?')} nodes | {f.get('active_alerts','?')} alerts")
    
    t1_load()
    t2_attacks()
    t3_db_crash()
    t4_memory()
    
    print("\n" + "=" * 60)
    print("  ULTIMATE STRESS VERDICT")
    print("=" * 60)
    for k, v in REPORT.items():
        s = v.get("status","?")
        print(f"  {'✅' if s=='PASS' else '⚠️' if s=='WARN' else '❌'} {k}: {s}")
    
    passed = sum(1 for v in REPORT.values() if v.get("status")=="PASS")
    total = len([v for v in REPORT.values() if "status" in v])
    print(f"\n  SCORE: {passed}/{total} ({passed/total*100:.0f}%)")
    
    out = PROJECT / "tools" / "ultimate_stress_report.json"
    out.write_text(json.dumps(REPORT, indent=2, default=str))
    print(f"  Report: {out}")
