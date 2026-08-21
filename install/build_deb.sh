#!/bin/bash
set -e

ROOT=/workspace/dfim
TMP=/tmp/dfim-deb-build
OUTPUT=$ROOT/install

echo "=== DFIM DEB Package Builder ==="

# Clean
rm -rf $TMP
mkdir -p $TMP/DEBIAN
mkdir -p $TMP/usr/bin
mkdir -p $TMP/usr/share/dfim
mkdir -p $TMP/etc/systemd/system
chmod 755 $TMP
chmod 755 $TMP/DEBIAN

# Binary
cp $ROOT/target/release/dfim_management_api $TMP/usr/bin/
chmod 755 $TMP/usr/bin/dfim_management_api

# Dashboard
cp $ROOT/dfim_management_api/dashboard.html $TMP/usr/share/dfim/

# SDK
cp $ROOT/dfim_management_api/dfim_client.py $TMP/usr/share/dfim/
chmod 755 $TMP/usr/share/dfim/dfim_client.py

# Control
cat > $TMP/DEBIAN/control << 'CTRL'
Package: dfim-management-api
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
 Includes embedded dashboard and Python SDK.
CTRL

# Systemd service
cat > $TMP/etc/systemd/system/dfim-management-api.service << 'SVC'
[Unit]
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
SVC

# Postinst
cat > $TMP/DEBIAN/postinst << 'POST'
#!/bin/sh
set -e
echo "DFIM Management API v0.1.0"
echo "  systemctl start dfim-management-api"
echo "  http://localhost:3000/health"
POST
chmod 755 $TMP/DEBIAN/postinst

# Build
dpkg-deb --build $TMP $OUTPUT/dfim-management-api_0.1.0_amd64.deb

echo ""
echo "=== DEB Package Built ==="
ls -la $OUTPUT/dfim-management-api_0.1.0_amd64.deb
dpkg-deb --info $OUTPUT/dfim-management-api_0.1.0_amd64.deb
dpkg-deb --contents $OUTPUT/dfim-management-api_0.1.0_amd64.deb
