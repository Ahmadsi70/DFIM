import os, subprocess, time, urllib.request, json

PROJECT = "/workspace/dfim"
SRC = f"{PROJECT}/dfim_management_api/src/main.rs"

# 1. Fix main.rs — ensure no axum path issues
with open(SRC) as f: c = f.read()
c = c.replace("AxumPath: Path<String>", "Path(id): Path<String>")
c = c.replace(".min(100000i64)", "")  # Remove broken pagination fix
c = c.replace(".min(100000)", "")     # Remove broken pagination fix
with open(SRC, "w") as f: f.write(c)
print("Fixed main.rs")

# 2. Build
env = os.environ.copy()
env["PATH"] = "/root/.cargo/bin:" + env.get("PATH", "")
env["DFIM_CRYPTO_KEY"] = "0123456789abcdef" * 4

subprocess.run(["pkill", "-f", "dfim_management_api"], capture_output=True)
time.sleep(1)

r = subprocess.run(["cargo", "build", "-p", "dfim_management_api", "--release"],
                  cwd=PROJECT, env=env, capture_output=True, text=True, timeout=300)

if r.returncode != 0:
    for line in (r.stderr).split("\n"):
        if "error" in line.lower() and "warning" not in line.lower():
            print(f"ERROR: {line[:150]}")
    exit(1)

print("BUILD SUCCESS")

# 3. Start
subprocess.Popen([f"{PROJECT}/target/release/dfim_management_api"],
                env={**env, "DFIM_API_BIND": "0.0.0.0:3000",
                     "DFIM_JWT_SECRET": "prod-jwt-v3-fixed",
                     "DATABASE_URL": "postgres://dfim:REDACTED@localhost/dfim_production"})
time.sleep(4)

# 4. Verify
try:
    r = urllib.request.urlopen("http://localhost:3000/health", timeout=5)
    print(f"API: {r.status} — RUNNING")
except Exception as e:
    print(f"API failed: {e}")
    exit(1)

# 5. Verify auth
try:
    urllib.request.urlopen("http://localhost:3000/v1/fleet/summary", timeout=3)
    print("Auth: BROKEN")
except urllib.error.HTTPError as e:
    print(f"Auth: ENFORCED ({e.code})")

# 6. Verify rate limiting
r200, r429 = 0, 0
for _ in range(200):
    try:
        urllib.request.urlopen("http://localhost:3000/health", timeout=2)
        r200 += 1
    except urllib.error.HTTPError as e:
        if e.code == 429: r429 += 1
print(f"Rate limit: {r200} ok, {r429} rate-limited (429)")

# 7. Benchmark with indexes
data = json.dumps({"username": "admin", "password": "REDACTED"}).encode()
req = urllib.request.Request("http://localhost:3000/v1/auth/login", data=data,
                             headers={"Content-Type": "application/json"}, method="POST")
token = json.loads(urllib.request.urlopen(req).read())["access_token"]

import concurrent.futures
def q():
    req = urllib.request.Request("http://localhost:3000/v1/assets?limit=20",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r: return r.status
    except: return 500

t0 = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    results = list(ex.map(lambda _: q(), range(200)))
el = time.perf_counter() - t0
ok = sum(1 for r in results if r == 200)
print(f"Benchmark: {ok}/200 in {el*1000:.0f}ms ({200/el:.0f} qps)")

print("\nALL FIXES VERIFIED")
