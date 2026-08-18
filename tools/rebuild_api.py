#!/usr/bin/env python3
"""Fix and rebuild dfim_management_api with all security patches."""
import os, subprocess, shutil

# Fix the broken handler signatures in main.rs
path = "/workspace/dfim/dfim_management_api/src/main.rs"
with open(path) as f:
    content = f.read()

# Fix mangled signatures
content = content.replace("AxumAxumPath: Path<String>", "Path(id): Path<String>")

with open(path, "w") as f:
    f.write(content)

print("Fixed main.rs handler signatures")

# Build
env = os.environ.copy()
env["PATH"] = "/root/.cargo/bin:" + env.get("PATH", "")
env["DFIM_CRYPTO_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

r = subprocess.run(["cargo", "build", "-p", "dfim_management_api", "--release"],
                  cwd="/workspace/dfim", env=env, capture_output=True, text=True, timeout=300)

if r.returncode == 0:
    print("BUILD SUCCESS")
else:
    print("BUILD FAILED")
    # Show errors
    for line in (r.stderr + r.stdout).split("\n"):
        if "error" in line.lower() and "warning" not in line.lower():
            print(line[:200])
