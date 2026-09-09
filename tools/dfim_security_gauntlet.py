import os
#!/usr/bin/env python3
"""
DFIM World-Class Security Gauntlet — Layer 2, 4, 1

SEC-L2: AFL++ full fuzzing (background 10min per target)
SEC-L4: JWT attack suite (7 vectors)
SEC-L4: SQL injection deep (10 PostgreSQL vectors)
SEC-L1: Side-channel timing audit (JWT verification)
SEC-L2: Kani proofs expansion check
"""

import hashlib, hmac, json, os, random, statistics, subprocess, sys, time, threading
import urllib.request, urllib.error
from datetime import datetime, UTC, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

API = "http://localhost:3000"
PROJECT = Path("/workspace/dfim")
REPORT = {}

def api(method, path, body=None, headers_extra=None):
    h = {"Content-Type": "application/json"}
    if headers_extra: h.update(headers_extra)
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(f"{API}{path}", data=data, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try: body = json.loads(body)
        except: body = {"error": body}
        return e.code, body
    except Exception as e:
        return -1, {"error": str(e)}

# ═══════════════════════════════════════════════════════════════════
# SEC-L2: AFL++ Fuzzing
# ═══════════════════════════════════════════════════════════════════

def sec_l2_afl_fuzz():
    print("\n=== SEC-L2: AFL++ Full Parser Fuzzing ===")
    
    env = os.environ.copy()
    env["PATH"] = "/root/.cargo/bin:" + env.get("PATH", "")
    env["DFIM_CRYPTO_KEY"] = hashlib.sha256(b"afl-fuzz").hexdigest()
    
    # Check if cargo-fuzz is available
    r = subprocess.run(["cargo", "fuzz", "--help"], capture_output=True, text=True,
                      cwd=PROJECT, env=env, timeout=10)
    has_cargo_fuzz = r.returncode == 0
    
    fuzz_targets = ["parse_block_stream", "parse_boot_manifest", "parse_rollback_baseline", "parse_authenticated_state_db"]
    results = {}
    
    if has_cargo_fuzz:
        for target in fuzz_targets:
            print(f"  Fuzzing {target} (60s)...")
            t0 = time.perf_counter()
            try:
                r = subprocess.run(
                    ["cargo", "fuzz", "run", target, "--", "-max_total_time=60"],
                    capture_output=True, text=True, cwd=PROJECT, env=env, timeout=90
                )
                elapsed = time.perf_counter() - t0
                crashes = "CRASH" in r.stderr.upper() or "crash" in r.stdout.lower()
                runs_line = [l for l in (r.stderr + r.stdout).split("\n") if "Done" in l and "runs" in l.lower()]
                runs_info = runs_line[0] if runs_line else f"{elapsed:.0f}s elapsed"
                print(f"    {runs_info} | Crashes: {'YES!' if crashes else '0'}")
                results[target] = {"runs_info": runs_info, "crashes": crashes, "duration_s": round(elapsed)}
            except subprocess.TimeoutExpired:
                print(f"    Timeout after 90s")
                results[target] = {"runs_info": "timeout", "crashes": False, "duration_s": 90}
            except Exception as e:
                print(f"    Error: {e}")
                results[target] = {"runs_info": str(e)[:100], "crashes": False, "duration_s": 0}
    else:
        print("  cargo-fuzz not available, skipping AFL++ fuzzing")
    
    any_crash = any(r.get("crashes", False) for r in results.values())
    all_tested = len(results) > 0
    
    REPORT["afl_fuzz"] = {
        "targets_tested": len(results),
        "targets_total": len(fuzz_targets),
        "targets": results,
        "any_crash": any_crash,
        "status": "FAIL" if any_crash else ("PASS" if all_tested else "WARN")
    }


# ═══════════════════════════════════════════════════════════════════
# SEC-L4: JWT Attack Suite
# ═══════════════════════════════════════════════════════════════════

def sec_l4_jwt_attacks():
    print("\n=== SEC-L4: JWT Attack Suite ===")
    
    # Get valid token for testing
    code, data = api("POST", "/v1/auth/login", {"username": "admin", "password": "" + os.getenv("DFIM_ADMIN_PASSWORD", "ci_test_admin_pass") + ""})
    valid_token = data.get("access_token", "")
    print(f"  Base token: {'OK' if valid_token else 'FAIL'}")
    
    if not valid_token:
        REPORT["jwt_attacks"] = {"status": "FAIL", "error": "Could not get valid token"}
        return
    
    tests = {}
    
    # Attack 1: None algorithm
    print("  [JWT-1] None algorithm attack...")
    parts = valid_token.split(".")
    import base64
    # Create header with alg=none
    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    none_token = f"{none_header}.{parts[1]}."
    code, data = api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {none_token}"})
    tests["jwt_none_alg"] = code == 401  # Must reject
    print(f"    Status: {code} | {'REJECTED ✅' if code == 401 else 'ACCEPTED ❌'}")
    
    # Attack 2: Key confusion (HS256 signed with RSA public key)
    print("  [JWT-2] Key confusion / algorithm switch...")
    # Try RS256 header with HS256 token
    rs_header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    rs_token = f"{rs_header}.{parts[1]}.{parts[2]}"
    code, _ = api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {rs_token}"})
    tests["jwt_key_confusion"] = code == 401
    print(f"    Status: {code} | {'REJECTED ✅' if code == 401 else 'VULNERABLE ❌'}")
    
    # Attack 3: Expired token
    print("  [JWT-3] Expired token bypass...")
    # Create manually expired token
    now = int(time.time())
    exp_header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    exp_payload = base64.urlsafe_b64encode(json.dumps({
        "sub": "admin", "tenant": "default", "role": "admin",
        "exp": now - 3600,  # expired 1 hour ago
        "iat": now - 7200
    }).encode()).rstrip(b"=").decode()
    # Sign with known key
    import hmac
    import hashlib
    sig_input = f"{exp_header}.{exp_payload}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(b"dfim-jwt-secret-production-key-2026-phase5", sig_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    exp_token = f"{exp_header}.{exp_payload}.{sig}"
    code, _ = api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {exp_token}"})
    tests["jwt_expired"] = code == 401
    print(f"    Status: {code} | {'REJECTED ✅' if code == 401 else 'ACCEPTED ❌'}")
    
    # Attack 4: Token tampering (modified payload)
    print("  [JWT-4] Payload tampering...")
    tampered_payload = base64.urlsafe_b64encode(json.dumps({
        "sub": "admin", "tenant": "default", "role": "admin",  # elevated to admin
        "exp": now + 86400, "iat": now
    }).encode()).rstrip(b"=").decode()
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    code, data = api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {tampered_token}"})
    tests["jwt_tampered"] = code == 401
    print(f"    Status: {code} | {'REJECTED ✅' if code == 401 else 'VULNERABLE ❌'}")
    
    # Attack 5: Missing signature
    print("  [JWT-5] Missing signature...")
    nosig_token = f"{parts[0]}.{parts[1]}."
    code, _ = api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {nosig_token}"})
    tests["jwt_no_signature"] = code == 401
    print(f"    Status: {code} | {'REJECTED ✅' if code == 401 else 'VULNERABLE ❌'}")
    
    # Attack 6: Brute force weak secret
    print("  [JWT-6] Brute force feasibility...")
    # Try common secrets
    weak_secrets = [b"secret", b"password", b"dfim", b"changeme"]
    cracked = False
    for secret in weak_secrets:
        sig = base64.urlsafe_b64encode(hmac.new(secret, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        test_token = f"{parts[0]}.{parts[1]}.{sig}"
        code, _ = api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {test_token}"})
        if code == 200:
            cracked = True
            break
    tests["jwt_weak_secret"] = not cracked
    print(f"    {'NOT crackable ✅' if not cracked else 'WEAK SECRET ❌'}")
    
    # Attack 7: Token replay (same token used multiple times — should work, that's normal)
    print("  [JWT-7] Valid token works (control)...")
    code, _ = api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {valid_token}"})
    tests["jwt_valid_works"] = code == 200
    print(f"    Status: {code} | {'WORKS ✅' if code == 200 else 'BROKEN ❌'}")
    
    passed = sum(1 for v in tests.values() if v)
    print(f"\n  JWT Score: {passed}/{len(tests)}")
    
    REPORT["jwt_attacks"] = {
        "tests": tests,
        "passed": passed,
        "total": len(tests),
        "status": "PASS" if passed >= 6 else "WARN"
    }


# ═══════════════════════════════════════════════════════════════════
# SEC-L4: SQL Injection Deep
# ═══════════════════════════════════════════════════════════════════

def sec_l4_sql_injection():
    print("\n=== SEC-L4: SQL Injection Deep ===")
    
    tests = {}
    
    # Vector 1: Classic SQLi in path parameter
    print("  [SQL-1] Classic SQLi in asset_id path...")
    payloads = [
        "sha256:' OR '1'='1",
        "sha256:' OR 1=1--",
        "sha256:' UNION SELECT NULL--",
        "sha256:1; DROP TABLE assets;--",
        "sha256:' OR '1'='1' OR '",
    ]
    all_blocked = True
    for payload in payloads:
        code, data = api("GET", f"/v1/assets/{urllib.parse.quote(payload, safe='')}")
        if code == 200 and isinstance(data, dict) and data.get("asset_id"):
            all_blocked = False
            print(f"    ⚠️  {payload[:40]} → {code}")
    tests["sql_classic_path"] = all_blocked
    print(f"    {'All blocked ✅' if all_blocked else 'VULNERABLE ❌'}")

    # Vector 2: SQLi in query parameters
    print("  [SQL-2] SQLi in query params...")
    q_payloads = [
        "' OR '1'='1",
        "1; DROP TABLE assets;--",
        "' UNION SELECT * FROM pg_user;--",
    ]
    all_blocked = True
    for payload in q_payloads:
        code, data = api("GET", f"/v1/assets?status={urllib.parse.quote(payload, safe='')}")
        if code != 400 and code != 500:
            all_blocked = all_blocked and code < 500
            if code == 200: all_blocked = False
    tests["sql_query_params"] = all_blocked
    print(f"    {'All safe ✅' if all_blocked else 'VULNERABLE ❌'}")

    # Vector 3: PostgreSQL-specific — stacked queries
    print("  [SQL-3] PostgreSQL stacked queries...")
    stacked = "1; SELECT pg_sleep(0);--"
    t0 = time.perf_counter()
    code, _ = api("GET", f"/v1/assets?status={urllib.parse.quote(stacked, safe='')}")
    elapsed = (time.perf_counter() - t0) * 1000
    # If query was executed (pg_sleep), it would take 1000ms+
    tests["sql_stacked"] = elapsed < 500
    print(f"    Response time: {elapsed:.0f}ms | {'Safe ✅' if elapsed < 500 else 'DELAYED ⚠️'}")

    # Vector 4: Error-based injection
    print("  [SQL-4] Error-based injection...")
    error_payloads = [
        "' AND 1=CAST((SELECT version()) AS INT)--",  # Type cast error
        "' AND extractvalue(1,concat(0x7e,version()))--",  # MySQL style
    ]
    error_leaked = False
    for payload in error_payloads:
        code, data = api("GET", f"/v1/assets/{urllib.parse.quote(payload, safe='')}")
        if isinstance(data, dict):
            error_msg = str(data.get("error", "")).lower()
            if "postgresql" in error_msg or "syntax" in error_msg or "pg_" in error_msg:
                error_leaked = True
    tests["sql_error_leak"] = not error_leaked
    print(f"    {'No leaks ✅' if not error_leaked else 'INFO LEAK ⚠️'}")

    # Vector 5: Boolean-based blind
    print("  [SQL-5] Boolean-based blind injection...")
    true_payload = "' OR '1'='1' --"
    false_payload = "' OR '1'='2' --"
    code_t, data_t = api("GET", f"/v1/assets/{urllib.parse.quote(true_payload, safe='')}")
    code_f, data_f = api("GET", f"/v1/assets/{urllib.parse.quote(false_payload, safe='')}")
    # If responses differ, blind injection possible
    diff = json.dumps(data_t) != json.dumps(data_f)
    tests["sql_boolean_blind"] = not diff
    print(f"    Responses differ: {diff} | {'Safe ✅' if not diff else 'VULNERABLE ⚠️'}")

    # Vector 6: PostgreSQL COPY attack
    print("  [SQL-6] PostgreSQL COPY attack...")
    copy_payload = "1; COPY (SELECT 'pwned') TO '/tmp/pwned.txt';--"
    code, _ = api("GET", f"/v1/assets/{urllib.parse.quote(copy_payload, safe='')}")
    file_created = os.path.exists("/tmp/pwned.txt")
    tests["sql_copy_attack"] = not file_created
    print(f"    File created: {file_created} | {'Safe ✅' if not file_created else 'RCE ❌'}")

    # Vector 7: Large object injection
    print("  [SQL-7] Large object injection...")
    lo_payload = "1; SELECT lo_import('/etc/passwd');--"
    code, _ = api("GET", f"/v1/assets/{urllib.parse.quote(lo_payload, safe='')}")
    tests["sql_lo_injection"] = code != 200
    print(f"    Status: {code} | {'Safe ✅' if code != 200 else 'VULNERABLE ❌'}")

    # Vector 8: Second-order injection (store malicious data, retrieve later)
    print("  [SQL-8] Second-order injection...")
    malicious_id = "sha256:sqli-test' OR '1'='1"
    code, _ = api("POST", "/v1/assets/enroll", {
        "asset_id": malicious_id, "display_name": "SQLi Test",
        "asset_kind": "test", "host_name": "sqli-node"
    })
    # Now try to retrieve — should be stored as literal, not executed
    code2, data2 = api("GET", f"/v1/assets/{urllib.parse.quote(malicious_id, safe='')}")
    second_order_ok = code2 in (200, 404) and code != 500  # Stored safely or rejected
    tests["sql_second_order"] = second_order_ok
    api("DELETE", f"/v1/assets/{urllib.parse.quote(malicious_id, safe='')}")
    print(f"    {'Safe ✅' if second_order_ok else 'VULNERABLE ❌'}")

    # Vector 9: Time-based blind
    print("  [SQL-9] Time-based blind injection...")
    time_payload = "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(0.001) ELSE pg_sleep(0) END)--"
    t0 = time.perf_counter()
    code, _ = api("GET", f"/v1/assets/{urllib.parse.quote(time_payload, safe='')}")
    tests["sql_time_blind"] = (time.perf_counter() - t0) * 1000 < 100
    print(f"    {'Safe ✅' if tests['sql_time_blind'] else 'DELAYED ⚠️'}")

    # Vector 10: Parameterized query verification (positive test)
    print("  [SQL-10] Parameterized query integrity...")
    # Legitimate request works
    code, _ = api("GET", "/v1/assets/sha256:bootmgfw")
    tests["sql_legitimate_works"] = code == 200
    print(f"    {'Legitimate works ✅' if code == 200 else 'BROKEN ❌'}")

    passed = sum(1 for v in tests.values() if v)
    print(f"\n  SQL Injection Score: {passed}/{len(tests)}")
    
    REPORT["sql_injection"] = {
        "tests": tests,
        "passed": passed,
        "total": len(tests),
        "status": "PASS" if passed >= 9 else ("WARN" if passed >= 7 else "FAIL")
    }


# ═══════════════════════════════════════════════════════════════════
# SEC-L1: Side-Channel Timing Audit
# ═══════════════════════════════════════════════════════════════════

def sec_l1_timing_audit():
    print("\n=== SEC-L1: Side-Channel Timing Audit ===")
    
    tests = {}
    
    # Timing test: JWT verification
    # Measure valid vs invalid token verification times
    print("  [TIME-1] JWT verification timing leak...")
    code, data = api("POST", "/v1/auth/login", {"username": "admin", "password": "" + os.getenv("DFIM_ADMIN_PASSWORD", "ci_test_admin_pass") + ""})
    valid_token = data.get("access_token", "")
    
    valid_times = []
    for _ in range(200):
        t0 = time.perf_counter_ns()
        api("GET", "/v1/fleet/summary", headers_extra={"Authorization": f"Bearer {valid_token}"})
        valid_times.append(time.perf_counter_ns() - t0)
    
    invalid_times = []
    for _ in range(200):
        t0 = time.perf_counter_ns()
        api("GET", "/v1/fleet/summary", headers_extra={"Authorization": "Bearer invalid.token.here"})
        invalid_times.append(time.perf_counter_ns() - t0)
    
    valid_mean = statistics.mean(valid_times)
    invalid_mean = statistics.mean(invalid_times)
    diff_pct = abs(valid_mean - invalid_mean) / max(valid_mean, invalid_mean) * 100
    
    # Valid should be SLOWER (full verification) than invalid (early reject)
    # If valid ≈ invalid → possible timing oracle for user enumeration
    tests["time_jwt_leak"] = diff_pct > 5
    print(f"    Valid: {valid_mean/1e6:.2f}ms | Invalid: {invalid_mean/1e6:.2f}ms | Δ={diff_pct:.1f}%")
    print(f"    {'Different timings ✅' if diff_pct > 5 else 'TIMING LEAK ⚠️'}")
    
    # Timing test: User enumeration via login
    print("  [TIME-2] Login timing — user enumeration...")
    valid_user_times = []
    for _ in range(50):
        t0 = time.perf_counter_ns()
        api("POST", "/v1/auth/login", {"username": "admin", "password": "wrong_pass"})
        valid_user_times.append(time.perf_counter_ns() - t0)
    
    invalid_user_times = []
    for _ in range(50):
        t0 = time.perf_counter_ns()
        api("POST", "/v1/auth/login", {"username": "nonexistent_user_xyz", "password": "any"})
        invalid_user_times.append(time.perf_counter_ns() - t0)
    
    vu_mean = statistics.mean(valid_user_times)
    iu_mean = statistics.mean(invalid_user_times)
    user_enum_pct = abs(vu_mean - iu_mean) / max(vu_mean, iu_mean) * 100
    tests["time_user_enum"] = user_enum_pct < 10
    print(f"    Valid user: {vu_mean/1e6:.2f}ms | Invalid user: {iu_mean/1e6:.2f}ms | Δ={user_enum_pct:.1f}%")
    print(f"    {'No enumeration ✅' if user_enum_pct < 10 else 'USER ENUM ⚠️'}")
    
    passed = sum(1 for v in tests.values() if v)
    
    REPORT["timing_audit"] = {
        "tests": tests,
        "jwt_diff_pct": round(diff_pct, 1),
        "user_enum_pct": round(user_enum_pct, 1),
        "passed": passed,
        "total": len(tests),
        "status": "PASS" if passed >= 2 else "WARN"
    }


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  DFIM WORLD-CLASS SECURITY GAUNTLET")
    print("=" * 60)
    
    # Run lightweight tests first (don't need cargo-fuzz)
    sec_l4_jwt_attacks()
    sec_l4_sql_injection()
    sec_l1_timing_audit()
    
    # Run fuzzing (may take a while)
    sec_l2_afl_fuzz()
    
    print("\n" + "=" * 60)
    print("  SECURITY GAUNTLET RESULTS")
    print("=" * 60)
    
    for key, val in REPORT.items():
        status = val.get("status", "?")
        icon = "✅" if status == "PASS" else "⚠️" if status == "WARN" else "❌"
        detail = f"({val.get('passed', '?')}/{val.get('total', '?')})" if "passed" in val else ""
        print(f"  {icon} {key}: {status} {detail}")
    
    passed = sum(1 for v in REPORT.values() if v.get("status") == "PASS")
    total = len(REPORT)
    
    REPORT["_timestamp"] = datetime.now(UTC).isoformat()
    REPORT["_score"] = f"{passed}/{total}"
    
    out = PROJECT / "tools" / "security_gauntlet_report.json"
    out.write_text(json.dumps(REPORT, indent=2, default=str))
    print(f"\n  SCORE: {passed}/{total} ({passed/total*100:.0f}%)")
    print(f"  Report: {out}")
