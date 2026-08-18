#!/usr/bin/env python3
"""Diagnose main.rs issues."""
path = "/workspace/dfim/dfim_management_api/src/main.rs"
with open(path) as f:
    lines = f.readlines()

for i, line in enumerate(lines, 1):
    if "fn " in line and ("asset" in line.lower() or "policy" in line.lower() or "alert" in line.lower() or "node" in line.lower()):
        print(f"L{i}: {line.rstrip()}")
    if "Axum" in line:
        print(f"L{i} (AXUM): {line.rstrip()}")
