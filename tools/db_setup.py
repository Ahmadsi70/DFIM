import subprocess
cmds = [
    "CREATE USER dfim WITH PASSWORD 'REDACTED';",
    "CREATE DATABASE dfim_production OWNER dfim;",
    "GRANT ALL PRIVILEGES ON DATABASE dfim_production TO dfim;",
]
for cmd in cmds:
    r = subprocess.run(["su", "-l", "postgres", "-c", f"psql -c \"{cmd}\""], capture_output=True, text=True)
    if r.returncode != 0 and "already exists" not in r.stderr:
        print(f"WARN: {r.stderr[:200]}")
print("DB setup complete")
