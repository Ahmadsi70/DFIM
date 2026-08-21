import os, subprocess
env = os.environ.copy()
env["PATH"] = "/root/.cargo/bin:" + env.get("PATH", "")
env["DFIM_CRYPTO_KEY"] = "0123456789abcdef" * 4
r = subprocess.run(["cargo", "build", "-p", "dfim_management_api", "--release"],
                  cwd="/workspace/dfim", env=env, capture_output=True, text=True, timeout=300)
for line in (r.stderr + r.stdout).split("\n"):
    if "error" in line.lower() and "warning" not in line.lower():
        print(line[:200])
