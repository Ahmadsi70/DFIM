#!/usr/bin/env python3
import subprocess, sys

# Install deps
subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-q",
                "pqcrypto", "numpy", "scikit-learn"], check=False)

# Verify
try:
    from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
    print("Dilithium2: OK")
except Exception as e:
    print(f"Dilithium2: FAIL - {e}")

try:
    from sklearn.ensemble import IsolationForest
    import numpy
    print("sklearn+numpy: OK")
except Exception as e:
    print(f"sklearn: FAIL - {e}")
