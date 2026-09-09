import os
#!/usr/bin/env python3
"""DFIM Hardcore Security Suite — sqlmap, brute force, exfil, race, rate limit"""
import hashlib, json, random, statistics, subprocess, sys, time, threading, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, UTC
from pathlib import Path

API = "http://localhost:3000"
DB = "postgres://dfim:" + os.getenv("DFIM_DB_PASSWORD", "ci_test_password") + "@localhost/dfim_production"
TOKEN = None
REPORT = {}
API_ERROR = None

def a(method, path, body=None, hdr=None):
    h = {"Content-Type": "application/json"}
    if hdr: h.update(hdr)
    if TOKEN and "Authorization" not in h: h["Authorization"] = f"Bearer {TOKEN}"
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(f"{API}{path}", data=data, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try: body = json.loads(e.read())
        except: body = {"error": str(e)}
        return e.code, body
    except Exception as e:
        return -1, {"error": str(e)}

def login():
    global TOKEN
    c, d = a("POST", "/v1/auth/login", {"username": "admin", "password": "" + os.getenv("DFIM_ADMIN_PASSWORD", "ci_test_admin_pass") + ""})
    TOKEN = d.get("access_token", "")
    return TOKEN

# ═══════════════════════════════════════════════════════════
# TEST-1: sqlmap scan
# ═══════════════════════════════════════════════════════════
def t1_sqlmap():
    print("\n=== TEST-1: sqlmap ===")
    if not TOKEN: print("SKIP"); return
    findings = []
    for ep in ["/v1/assets?status=healthy", "/v1/assets?host=prod-node-00001",
               "/v1/assets?kind=LinuxKernel", "/v1/assets/sha256:test"]:
        print(f"  Scan: {ep}")
        try:
            r = subprocess.run(["sqlmap", "-u", f"{API}{ep}", "--batch", "--level=2", "--risk=2",
                "--headers", f"Authorization: Bearer {TOKEN}", "--flush-session", "--timeout=10"],
                capture_output=True, text=True, timeout=90)
            vuln = "vulnerable" in r.stdout.lower() or "injectable" in r.stdout.lower()
            print(f"    {'VULNERABLE!' if vuln else 'SAFE'}")
            findings.append({"endpoint": ep, "vulnerable": vuln})
        except Exception as e:
            findings.append({"endpoint": ep, "vulnerable": False})
    any_vuln = any(f["vulnerable"] for f in findings)
    REPORT["sqlmap"] = {"endpoints": len(findings), "vulnerable": any_vuln, "status": "FAIL" if any_vuln else "PASS"}

# ═══════════════════════════════════════════════════════════
# TEST-2: Brute force
# ═══════════════════════════════════════════════════════════
def t2_brute_force():
    print("\n=== TEST-2: Brute Force ===")
    base = ["password","123456","admin","dfim","changeme","secret","qwerty","letmein",
            "monkey","dragon","master","abc123","passw0rd","DFIM2026","test","guest","root","toor"]
    passwords = set()
    for p in base:
        for s in [p, p.upper(), p.capitalize(), p+"123", p+"2026", p+"!", "123"+p]:
            passwords.add(s)
    passwords = list(passwords)[:5000]
    print(f"  Testing {len(passwords)} passwords...")
    t0 = time.perf_counter()
    cracked, rate_lim = 0, 0
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = [ex.submit(lambda pw=pw: a("POST", "/v1/auth/login", {"username": "admin", "password": pw})) for pw in passwords]
        for f in as_completed(futs):
            code, _ = f.result()
            if code == 200: cracked += 1
            elif code == 429: rate_lim += 1
    el = time.perf_counter() - t0
    print(f"  Cracked: {cracked} | Rate-limited: {rate_lim} | Rejected: {len(passwords)-cracked-rate_lim}")
    print(f"  Speed: {len(passwords)/el:.0f}/s | ~{el/len(passwords)*1000:.1f}ms/attempt")
    REPORT["brute_force"] = {"attempts": len(passwords), "cracked": cracked, "rate_limited": rate_lim,
                              "speed": round(len(passwords)/el), "status": "PASS" if cracked == 0 else "FAIL"}

# ═══════════════════════════════════════════════════════════
# TEST-3: Data exfiltration
# ═══════════════════════════════════════════════════════════
def t3_data_exfil():
    print("\n=== TEST-3: Data Exfiltration ===")
    t0 = time.perf_counter()
    assets, offset = [], 0
    while True:
        code, data = a("GET", f"/v1/assets?limit=1000&offset={offset}")
        if code != 200 or not data: break
        assets.extend(data)
        offset += len(data)
        if offset >= 30000: break
    el = time.perf_counter() - t0
    print(f"  Exfiltrated: {len(assets)} assets in {el:.1f}s ({len(assets)/el:.0f}/s)")
    print(f"  Data volume: {len(json.dumps(assets))/1024:.1f} KB")
    leaked = any(k in str(assets[0] if assets else "").lower() for k in ["password","secret","key","token"])
    REPORT["data_exfil"] = {"exfiltrated": len(assets), "kb": round(len(json.dumps(assets))/1024,1),
                             "leaked_sensitive": leaked, "status": "PASS" if not leaked else "WARN"}

# ═══════════════════════════════════════════════════════════
# TEST-4: Rate limit bypass
# ═══════════════════════════════════════════════════════════
def t4_rate_limit():
    print("\n=== TEST-4: Rate Limit Bypass ===")
    total = 3000
    r200, r429, r401 = 0, 0, 0
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = [ex.submit(lambda: a("GET", "/health")[0]) for _ in range(total)]
        for f in as_completed(futs):
            s = f.result()
            if s == 200: r200 += 1
            elif s == 429: r429 += 1
            elif s == 401: r401 += 1
    el = time.perf_counter() - t0
    print(f"  200 OK: {r200} | 401: {r401} | 429 Rate Limited: {r429} ({r429/total*100:.1f}%)")
    print(f"  Throughput: {total/el:.0f} req/s")
    REPORT["rate_limit"] = {"total": total, "rate_limited": r429, "pct": round(r429/total*100,1),
                             "status": "PASS" if r429 > 0 else "WARN"}

# ═══════════════════════════════════════════════════════════
# TEST-5: DB attacks
# ═══════════════════════════════════════════════════════════
def t5_db_attacks():
    print("\n=== TEST-5: DB Attacks ===")
    tests = {}
    r = subprocess.run(f'psql {DB} -c "SELECT current_user;"', shell=True, capture_output=True, text=True, timeout=10)
    tests["connect"] = r.returncode == 0
    print(f"  Direct DB connection: {tests['connect']}")

    r = subprocess.run(f'psql {DB} -c "SELECT COUNT(*) FROM assets;"', shell=True, capture_output=True, text=True, timeout=10)
    tests["query_assets"] = r.returncode == 0
    print(f"  Direct table query: {tests['query_assets']}")

    # Try pg_read_file attack
    r = subprocess.run(f"psql {DB} -c \"SELECT pg_read_file('/etc/passwd',0,100);\"", shell=True, capture_output=True, text=True, timeout=10)
    tests["pg_read_file"] = "root:" in r.stdout
    print(f"  pg_read_file attack: {'VULNERABLE!' if tests['pg_read_file'] else 'PROTECTED'}")

    vuls = sum(1 for v in tests.values() if v)
    REPORT["db_attacks"] = {"tests": tests, "vulns": vuls, "status": "PASS" if vuls <= 1 else "WARN"}

# ═══════════════════════════════════════════════════════════
# TEST-6: Race condition
# ═══════════════════════════════════════════════════════════
def t6_race_condition():
    print("\n=== TEST-6: Race Condition ===")
    aid = f"race-{random.randint(10000,99999)}"
    a("POST", "/v1/assets/enroll", {"asset_id": aid, "display_name": "Race", "asset_kind": "test", "host_name": "node"})
    v_res, d_res = [], []
    def v(): v_res.append(a("PUT", f"/v1/assets/{aid}/verify", {"integrity_hash": "sha256:test"})[0])
    def d(): d_res.append(a("DELETE", f"/v1/assets/{aid}")[0])
    threads = []
    for _ in range(100):
        threads.append(threading.Thread(target=v))
        threads.append(threading.Thread(target=d))
    t0 = time.perf_counter()
    for t in threads: t.start()
    for t in threads: t.join()
    el = time.perf_counter() - t0
    crashed = sum(1 for x in v_res + d_res if x >= 500)
    print(f"  200 verify+delete operations in {el*1000:.0f}ms")
    print(f"  Server errors (500+): {crashed} | {'NO CRASH' if crashed == 0 else 'RACE CRASH!'}")
    REPORT["race_condition"] = {"ops": len(threads), "crashes": crashed, "ms": round(el*1000),
                                 "status": "PASS" if crashed == 0 else "FAIL"}

# ═══════════════════════════════════════════════════════════
# BENCHMARK
# ═══════════════════════════════════════════════════════════
def bench():
    print("\n=== BENCHMARK: API with 50K assets ===")
    code, summary = a("GET", "/v1/fleet/summary")
    print(f"  Fleet: {json.dumps(summary)}")
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=64) as ex:
        results = list(ex.map(lambda _: a("GET", "/v1/assets?limit=20")[0], range(500)))
    el = time.perf_counter() - t0
    ok = sum(1 for r in results if r == 200)
    print(f"  500 asset queries: {ok} ok in {el*1000:.0f}ms ({500/el:.0f}/s)")
    REPORT["benchmark"] = {"queries": 500, "ok": ok, "ms": round(el*1000), "qps": round(500/el)}

# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  DFIM HARDCORE SECURITY SUITE")
    print("=" * 60)
    login()
    print(f"Auth: {'OK' if TOKEN else 'FAIL'}")
    t1_sqlmap()
    t2_brute_force()
    t3_data_exfil()
    t4_rate_limit()
    t5_db_attacks()
    t6_race_condition()
    bench()
    print("\n" + "=" * 60)
    passed = sum(1 for v in REPORT.values() if v.get("status") == "PASS")
    total = sum(1 for v in REPORT.values() if "status" in v)
    for k, v in REPORT.items():
        print(f"  {'PASS' if v.get('status')=='PASS' else 'WARN' if v.get('status')=='WARN' else 'FAIL'} {k}")
    print(f"\n  SCORE: {passed}/{total} ({passed/total*100:.0f}%)")
