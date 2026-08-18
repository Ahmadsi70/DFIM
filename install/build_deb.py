#!/usr/bin/env python3
"""Build DEB package for dfim-management-api — complete from scratch."""
import os, shutil, subprocess

ROOT = "/workspace/dfim"
DEB = f"{ROOT}/install/deb"
BIN = f"{ROOT}/target/release/dfim_management_api"

if not os.path.exists(BIN):
    print(f"ERROR: Binary not found at {BIN}. Run `cargo build -p dfim_management_api --release` first.")
    exit(1)

# Clean and recreate with proper permissions
if os.path.exists(DEB):
    shutil.rmtree(DEB)
os.makedirs(f"{DEB}/DEBIAN")
os.makedirs(f"{DEB}/usr/bin")
os.makedirs(f"{DEB}/usr/share/dfim")
os.makedirs(f"{DEB}/etc/systemd/system")
# Force correct permissions on entire tree
os.chmod(DEB, 0o755)
for root, dirs, files in os.walk(DEB):
    for d in dirs:
        os.chmod(os.path.join(root, d), 0o755)
    for f in files:
        os.chmod(os.path.join(root, f), 0o644)

# control
with open(f"{DEB}/DEBIAN/control", "w") as f:
    f.write("""Package: dfim-management-api
Version: 0.1.0
Section: admin
Priority: optional
Architecture: amd64
Depends: systemd
Maintainer: DFIM Engineering <dfim@example.com>
Description: DFIM Central Fleet Integrity Management API
 Phase 1 Productization — Enterprise-grade firmware integrity orchestrator.
 Provides REST API for fleet-wide asset enrollment, integrity verification,
 policy enforcement, node registration, and security alert management.
 Includes embedded dashboard and OpenAPI 3.1 specification.
""")

# postinst
with open(f"{DEB}/DEBIAN/postinst", "w") as f:
    f.write("""#!/bin/sh
set -e
echo "DFIM Management API v0.1.0 installed."
echo "  Start: systemctl start dfim-management-api"
echo "  API:   http://localhost:3000/health"
echo "  Spec:  http://localhost:3000/openapi.json"
""")
os.chmod(f"{DEB}/DEBIAN/postinst", 0o755)

# Systemd service
with open(f"{DEB}/etc/systemd/system/dfim-management-api.service", "w") as f:
    f.write("""[Unit]
Description=DFIM Central Fleet Integrity Management API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/dfim-management-api
Restart=always
RestartSec=5
Environment=DFIM_API_BIND=0.0.0.0:3000
Environment=RUST_LOG=info
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
""")

# Binary
shutil.copy2(BIN, f"{DEB}/usr/bin/dfim-management-api")
os.chmod(f"{DEB}/usr/bin/dfim-management-api", 0o755)

# Dashboard
dash_src = f"{ROOT}/dfim_management_api/dashboard.html"
if os.path.exists(dash_src):
    shutil.copy2(dash_src, f"{DEB}/usr/share/dfim/")

# SDK
sdk_src = f"{ROOT}/dfim_management_api/dfim_client.py"
if os.path.exists(sdk_src):
    shutil.copy2(sdk_src, f"{DEB}/usr/share/dfim/")
    os.chmod(f"{DEB}/usr/share/dfim/dfim_client.py", 0o755)

# Build DEB
pkg_path = f"{ROOT}/install/dfim-management-api_0.1.0_amd64.deb"
subprocess.run(["dpkg-deb", "--build", DEB, pkg_path], check=True)

# Summary
size = os.path.getsize(pkg_path)
print(f"\nDEB package built: {pkg_path}")
print(f"Size: {size/1024:.0f} KB")

# Verify
r = subprocess.run(["dpkg-deb", "--info", pkg_path], capture_output=True, text=True)
print(r.stdout)

# List contents
print("Contents:")
subprocess.run(["dpkg-deb", "--contents", pkg_path])
