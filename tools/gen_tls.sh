#!/bin/bash
# TLS certificate generator for DFIM
CERT_DIR="${DFIM_TLS_DIR:-/etc/dfim/tls}"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
  -days 365 -nodes -subj "/CN=dfim-api/O=DFIM/OU=Security" 2>/dev/null
echo "TLS cert generated in $CERT_DIR"
echo "  cert: $CERT_DIR/cert.pem"
echo "  key:  $CERT_DIR/key.pem"
echo "Restart API with TLS enabled."
