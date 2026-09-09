---
layout: default
title: DFIM — Deterministic Firmware Integrity Matrix
---

<style>.markdown-body ul:first-child{display:none}.markdown-body h1{display:none}.markdown-body>p:first-child{display:none}</style>

# 🔐 DFIM — Deterministic Firmware Integrity Matrix

[![Rust](https://img.shields.io/badge/Rust-1.91.1-dea584?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/Ahmadsi70/DFIM/actions/workflows/ci.yml/badge.svg)](https://github.com/Ahmadsi70/DFIM/actions)
[![Fuzzing](https://github.com/Ahmadsi70/DFIM/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Ahmadsi70/DFIM/actions)
[![Formal Verification](https://github.com/Ahmadsi70/DFIM/actions/workflows/kani.yml/badge.svg)](https://github.com/Ahmadsi70/DFIM/actions)
[![CodeQL](https://github.com/Ahmadsi70/DFIM/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ahmadsi70/DFIM/actions)

> **Enterprise-grade firmware integrity enforcement from UEFI to kernel to userspace.**
> Deterministic Merkle-tree verification with Hamming FEC, eBPF LSM probes, UEFI boot guard, and formal proofs — all in Rust.

---

## 🏆 Benchmark: 95/100 — A+

| Dimension | Score | Grade |
|-----------|-------|-------|
| Merkle Tree Integrity | 100/100 | A+ |
| SHA-256 Throughput (2 GB/s) | 100/100 | A+ |
| eBPF Enforcement (<1 µs lookup) | 95/100 | A+ |
| Boot Validation (155 µs / 256 KB) | 100/100 | A+ |
| Real Provisioner/Verify (~7 ms) | 75/100 | B+ |
| API Concurrency (116K ops/s) | 95/100 | A+ |
| Fleet Simulation (650K nodes/s) | 100/100 | A+ |

**Verified against 735 real-world security files** — 99.86% tamper detection, 100% provision/verify on CVE exploits, malware patterns, firmware images, and adversarial edge cases. [Full report](SECURITY_BENCHMARK_REPORT.md)

---

## ✨ Features

### 🛡️ Multi-Ring Integrity
| Layer | Platform | Technology |
|-------|----------|------------|
| **Ring -1** (Hardware) | UEFI + TPM 2.0 | DFIMBOOT v2 signed manifests, P-256 ECDSA, anti-rollback |
| **Ring 0** (Kernel) | Linux | eBPF LSM probes, IMA appraisal, DenyEvents |
| **Ring 1** (Boot) | Windows | UEFI boot guard intercepts `bootmgfw.efi` |
| **Ring 3** (Userspace) | Windows + Linux | CLI provisioner, REST API, WASM plugins |

### 🔬 Cryptography
- **Merkle Tree** — O(log N) membership proofs with SHA-256
- **Hamming FEC** — Single-bit error correction for bit-rot detection
- **ECDSA P-256** — Signed DFIMBOOT v2 manifests
- **TPM 2.0** — Remote attestation with nonce-bound quotes over PCR 0/2/4/7/14
- **Constant-time** — Side-channel resistant comparisons (`subtle` crate)
- **FIPS 140-3** — Self-tests with NIST CAVP KAT vectors (ready for validation)

### 🏢 Enterprise Management
- **REST API** (axum + PostgreSQL) — JWT, RBAC, rate limiting, OpenAPI 3.1
- **SIEM Export** — Splunk HEC, Elastic ECS, Microsoft Sentinel CEF, Syslog, NDJSON
- **Monitoring** — Prometheus metrics, Grafana dashboards
- **WASM Plugin SDK** — Custom enforcement policies (PCI-DSS, NIST 800-53, GDPR)
- **Fleet Management** — Assets, policies, alerts, integrity coverage tracking

### ✅ Formal Verification
- **Kani Rust Verifier** — Mathematical proofs for parsers and integrity gates
- **Fuzz Testing** — 4 cargo-fuzz targets for parsers
- **No `unsafe`** — `#![deny(unsafe_code)]` in core engine

### 🔗 Supply Chain Security
- **Reproducible builds** — `SOURCE_DATE_EPOCH` pinned, SLSA v1.2 provenance
- **CycloneDX SBOM** — Generated per release
- **cargo-deny** — License compliance, yanked crate detection
- **CodeQL** — Static analysis in CI

---

## 🚀 Quick Start

### Prerequisites
```bash
# Install Rust 1.91.1 (or use rustup)
rustup install 1.91.1
rustup target add x86_64-pc-windows-msvc   # Windows
rustup target add x86_64-unknown-linux-gnu  # Linux
```

### Build & Run
```bash
# Clone
git clone https://github.com/Ahmadsi70/DFIM.git
cd DFIM

# Build the provisioner
cargo build --release -p dfim_cli_provisioner

# Provision a boot image
./target/release/dfim-provisioner provision /path/to/boot_image.bin

# Verify integrity
./target/release/dfim-provisioner verify /path/to/boot_image.bin
```

### Start the Management API
```bash
# With Docker Compose
cd deploy
docker-compose up -d

# Health check
curl http://localhost:3000/health
```

---

## 🏗️ Architecture

```
DFIM Workspace (7 crates)
═══════════════════════════════════════════════

┌─────────────────────────────────────────────────────┐
│  dfim_core_engine    — Layer-0: SHA-256, Merkle,    │
│                        Hamming FEC, FIPS, KDF       │
├─────────────────────────────────────────────────────┤
│  dfim_cli_provisioner — CLI: provision, verify,     │
│                          recover, attestation        │
├─────────────────────────────────────────────────────┤
│  dfim_windows_uefi    — UEFI boot guard for Windows │
├─────────────────────────────────────────────────────┤
│  dfim-ebpf / dfim-ebpf-user — Linux eBPF LSM probes │
├─────────────────────────────────────────────────────┤
│  dfim_management_api  — REST API, RBAC, SIEM export │
├─────────────────────────────────────────────────────┤
│  dfim_plugin_sdk      — WASM sandbox for policies   │
├─────────────────────────────────────────────────────┤
│  dfim_host_init       — Evaluation license gate     │
└─────────────────────────────────────────────────────┘
```

---

## 📁 Documentation

| Document | Description |
|----------|-------------|
| [`docs/security/THREAT_MODEL.md`](docs/security/THREAT_MODEL.md) | Comprehensive threat model |
| [`docs/security/ENFORCEMENT_POLICY.md`](docs/security/ENFORCEMENT_POLICY.md) | Enforcement policy architecture |
| [`docs/security/DFIMBOOT_V2.md`](docs/security/DFIMBOOT_V2.md) | Boot security specification v2 |
| [`docs/security/REMOTE_ATTESTATION.md`](docs/security/REMOTE_ATTESTATION.md) | TPM 2.0 attestation protocol |
| [`docs/security/COMPLIANCE_MAPPING.md`](docs/security/COMPLIANCE_MAPPING.md) | ISO 27001:2022 mapping |
| [`docs/enterprise/ENTERPRISE_SLA.md`](docs/enterprise/ENTERPRISE_SLA.md) | Service Level Agreements |
| [`docs/enterprise/PRODUCT_SECURITY_WHITE_PAPER.md`](docs/enterprise/PRODUCT_SECURITY_WHITE_PAPER.md) | Security white paper |
| [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md) | Operations guide |
| [`SECURITY_BENCHMARK_REPORT.md`](SECURITY_BENCHMARK_REPORT.md) | 735-file security benchmark |

---

## 🧪 Tested & Deployed

| Environment | Status |
|-------------|--------|
| Windows 11 (UEFI) | ✅ Verified |
| Ubuntu 24.04 (eBPF) | ✅ Verified |
| QEMU/KVM (Virtualized) | ✅ Verified |
| 735 Security Files | ✅ 99.86% tamper detection |

---

## 📜 License

**DFIM Community Edition** is licensed under **Apache 2.0** — see [LICENSE](LICENSE) for details.

**DFIM Enterprise Edition** adds advanced features: TPM attestation, FIPS 140-3 validation, SIEM connectors, WASM plugin SDK, premium support, and SLA. Contact us for licensing.

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](docs/community/CONTRIBUTING.md) and our [Code of Conduct](docs/community/CODE_OF_CONDUCT.md).

For **enterprise** or **partnership** inquiries, please [start a discussion](https://github.com/Ahmadsi70/DFIM/discussions).

---

## ⭐ Support

If you find DFIM useful:
- ⭐ **Star this repo** — it helps us grow
- 🐛 **Report issues** — bug reports and feature requests welcome
- 💬 **Join discussions** — ask questions, share use cases

---

<p align="center">
  <b>Deterministic Integrity. Built in Rust.</b>
</p>