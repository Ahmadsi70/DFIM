#!/usr/bin/env python3
"""Fix remaining issues and rebuild."""
path = "/workspace/dfim/dfim_management_api/src/main.rs"
with open(path) as f:
    c = f.read()

# Fix line 346
c = c.replace("AxumPath: Path<String>", "Path(id): Path<String>")

# Fix line 263 - missing Path(id) in verify_asset
# Pattern: verify_asset(State(state): State<AppState>, headers: header::HeaderMap,\n  Json(body)
old = "async fn verify_asset(State(state): State<AppState>, headers: header::HeaderMap,\n                      Json(body)"
new = "async fn verify_asset(State(state): State<AppState>, headers: header::HeaderMap,\n                      Path(id): Path<String>, Json(body)"
c = c.replace(old, new)

with open(path, "w") as f:
    f.write(c)

print("All fixes applied")

import os, subprocess
env = os.environ.copy()
env["PATH"] = "/root/.cargo/bin:" + env.get("PATH", "")
env["DFIM_CRYPTO_KEY"] = "0123456789abcdef" * 4

r = subprocess.run(["cargo", "build", "-p", "dfim_management_api", "--release"],
                  cwd="/workspace/dfim", env=env, capture_output=True, text=True, timeout=300)

if r.returncode == 0:
    print("BUILD SUCCESS!")
else:
    for line in (r.stderr).split("\n"):
        if "error" in line.lower() and "warning" not in line.lower():
            print(line[:200])
