#!/usr/bin/env python3
"""DFIM Revolutionary Development Roadmap – structured plan for product-market transformation.

Generates a full strategic roadmap across 4 phases (0→4) covering technical,
certification, market, and ecosystem dimensions.  Outputs JSON for CI gating
or Markdown for human review.

Usage:
    python dfim_revolutionary_roadmap.py              # Markdown report
    python dfim_revolutionary_roadmap.py --json        # JSON output
    python dfim_revolutionary_roadmap.py --validate    # Self-validation only
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Milestone:
    id: str
    title: str
    description: str
    deliverables: list[str]
    effort_weeks: int
    depends_on: list[str]  # milestone IDs
    risk: str              # "low" | "medium" | "high" | "critical"


@dataclass(frozen=True)
class Phase:
    ref: str
    title_fa: str
    title_en: str
    timeline: str
    goal: str
    milestones: list[Milestone]
    kpis: list[str]
    exit_criteria: list[str]


@dataclass(frozen=True)
class RevenueStream:
    name_fa: str
    name_en: str
    model: str
    target_market: str
    estimated_arr_range: str
    moat: str


@dataclass(frozen=True)
class Roadmap:
    version: str
    generated_at: str
    project_name: str
    vision: str
    phases: list[Phase]
    revenue_streams: list[RevenueStream]
    total_estimated_weeks: int
    critical_path_ids: list[str]


# ═══════════════════════════════════════════════════════════════════════════
# Roadmap Definition
# ═══════════════════════════════════════════════════════════════════════════

ROADMAP_VERSION = "1.0.0"
_VISION = (
    "DFIM 2.0 becomes the reference open-core firmware integrity platform "
    "trusted by telecom, defense, banking, and cloud-native operators worldwide – "
    "the de-facto standard for secure boot-chain enforcement across all platforms."
)

# --- Phase 0: شکاف‌زدایی و تثبیت --------------------------------------------------

PHASE0_MILESTONES = [
    Milestone(
        id="P0-M1",
        title="حذف وابستگی به IMA – eBPF مستقل",
        description=(
            "گسترش eBPF LSM hooks به `file_mmap`, `inode_permission`, و "
            "`file_open` برای appraisal مستقل بدون IMA کرنل. هر فایل محافظت‌شده "
            "توسط eBPF به تنهایی تایید می‌شود."
        ),
        deliverables=[
            "eBPF bpf_prog_type LSM hooks اضافی: mmap_file, inode_permission, file_open",
            "eBPF-side SHA-256 on-the-fly برای فایل‌های خوانده‌شده",
            "ماژول جدید `dfim_linux_kernel/src/appraisal.rs`",
            "تست‌های یکپارچگی Rust بین dfim_core_engine و dfim_linux_kernel",
        ],
        effort_weeks=8,
        depends_on=[],
        risk="high",
    ),
    Milestone(
        id="P0-M2",
        title="تست‌های یکپارچگی Rust بین crateها",
        description=(
            "ایجاد `tests/` cargo integration tests برای تمام جفت‌های crate: "
            "core↔cli, core↔uefi, core↔host_init, core↔linux_kernel."
        ),
        deliverables=[
            "tests/core_cli_integration.rs",
            "tests/core_uefi_integration.rs",
            "tests/core_host_init_integration.rs",
            "tests/core_linux_kernel_integration.rs",
            "CI workflow: cargo test --workspace --test '*'",
        ],
        effort_weeks=4,
        depends_on=[],
        risk="low",
    ),
    Milestone(
        id="P0-M3",
        title="انتزاع مسیر بوت UEFI",
        description=(
            "حذف هاردکد `bootmgfw.efi` و پشتیبانی از مسیرهای دلخواه بوت "
            "از طریق فایل پیکربندی `dfim_boot.json` روی ESP."
        ),
        deliverables=[
            "پارسر `dfim_boot.json` در dfim_windows_uefi",
            "پشتیبانی از چندین تصویر بوت (bootmgfw, bootmgfw-backup, custom)",
            "تست با مسیرهای مختلف در QEMU",
        ],
        effort_weeks=3,
        depends_on=[],
        risk="low",
    ),
    Milestone(
        id="P0-M4",
        title="حذف گیت لایسنس ۳۰ روزه از Production",
        description=(
            "فعال‌سازی production mode توسط `DFIM_PRODUCTION=1` یا کلید "
            "امضاشده در TPM NV. هیچ گونه expiry یا eval gate در Production باقی نماند."
        ),
        deliverables=[
            "Production activation via TPM NV sealed secret",
            "حذف کامل مسیر eval از بیلد production",
            "تست تولید بدون لایسنس",
        ],
        effort_weeks=2,
        depends_on=[],
        risk="medium",
    ),
    Milestone(
        id="P0-M5",
        title="Runtime Key Management با TPM NV",
        description=(
            "انتقال کلیدهای امضا و هویت از `build.rs` (کامپایل‌تایم) به "
            "TPM NV Index. چرخش کلید بدون rebuild ممکن می‌شود."
        ),
        deliverables=[
            "TPM NV Index definition for DFIM signing key",
            "UEFI: خواندن کلید از TPM NV به جای baked-in",
            "CLI: فرمان `dfim key-rotate` برای چرخش کلید",
            "تست چرخش کلید در QEMU + swtpm",
        ],
        effort_weeks=6,
        depends_on=[],
        risk="high",
    ),
    Milestone(
        id="P0-M6",
        title="تکمیل Recovery Qualification",
        description=(
            "تست‌های تخریبی: power-loss در حین recovery، UEFI capsule "
            "update، و بازیابی کامل سیستم از snapshot."
        ),
        deliverables=[
            "تست power-loss recovery (خاموشی تصادفی وسط نوشتن دیسک)",
            "تست UEFI capsule recovery",
            "مستند `RECOVERY_QUALIFICATION_REPORT.md`",
        ],
        effort_weeks=4,
        depends_on=[],
        risk="medium",
    ),
    Milestone(
        id="P0-M7",
        title="Telemetry GA – خروج از Beta",
        description=(
            "پایدارسازی OpenTelemetry Collector pipeline: TLS اجباری، "
            "retention policy خودکار، authentication با mTLS."
        ),
        deliverables=[
            "OTel Collector با mTLS client certificate",
            "Retention policy خودکار مبتنی بر حجم دیسک",
            "Health check endpoint + alert rule در Grafana",
        ],
        effort_weeks=3,
        depends_on=[],
        risk="low",
    ),
]

PHASE_0 = Phase(
    ref="PHASE-0",
    title_fa="فاز ۰: شکاف‌زدایی و تثبیت (Foundation)",
    title_en="Phase 0: Gap Closure & Foundation",
    timeline="هفته ۱ تا ۱۰ (۲.۵ ماه)",
    goal="رفع تمام کمبودهای بحرانی شناسایی‌شده در ارزیابی و تبدیل کد به یک محصول مهندسی‌شده",
    milestones=PHASE0_MILESTONES,
    kpis=[
        "امتیاز ارزیابی کلی: 82% → 95%",
        "تعداد تست‌های یکپارچگی Rust: 0 → ۱۰+",
        "تعداد وابستگی‌های خارجی (IMA, baked key): 3 → 0",
        "پوشش eBPF برای appraisal مستقل: ۰٪ → ۱۰۰٪ فایل‌های محافظت‌شده",
    ],
    exit_criteria=[
        "تمام ۹ کمبود بحرانی از ارزیابی رفع شده باشند",
        "امتیاز کلی ارزیابی >= 95%",
        "تست‌های یکپارچگی Rust بین تمام crateها وجود داشته باشد",
        "Production build بدون eval gate ممکن باشد",
    ],
)

# --- Phase 1: محصول‌سازی و بسته‌بندی --------------------------------------------

PHASE1_MILESTONES = [
    Milestone(
        id="P1-M1",
        title="بسته‌بندی Enterprise – Installer یکپارچه",
        description=(
            "ایجاد installer واحد برای Windows (MSI + UEFI capsule) و Linux "
            "(DEB/RPM + eBPF loader). نصب با یک کلیک/دستور."
        ),
        deliverables=[
            "Windows MSI installer با UEFI flash خودکار",
            "Linux DEB/RPM package با systemd unit",
            "eBPF auto-loader در startup",
            "Uninstall clean (remove UEFI variable + eBPF maps)",
        ],
        effort_weeks=6,
        depends_on=["P0-M4", "P0-M5"],
        risk="medium",
    ),
    Milestone(
        id="P1-M2",
        title="داشبورد مدیریت متمرکز (Central Management)",
        description=(
            "یک Web UI مبتنی بر React برای مدیریت fleet: مشاهده وضعیت "
            "integrity همه assetها، اعمال policy، approve/deny enrollment."
        ),
        deliverables=[
            "React SPA با authentication (OAuth2/OIDC)",
            "API backend (Rust/axum) برای management operations",
            "Telemetry aggregation از سراسر fleet",
            "Asset enrollment workflow (approve/pending/deny)",
        ],
        effort_weeks=10,
        depends_on=["P0-M7"],
        risk="high",
    ),
    Milestone(
        id="P1-M3",
        title="مستندات Production Operator",
        description=(
            "مستندات کامل برای اپراتورهای production: runbook, playbook, "
            "troubleshooting guide, disaster recovery."
        ),
        deliverables=[
            "OPERATOR_RUNBOOK.md – daily operations",
            "TROUBLESHOOTING_GUIDE.md – diagnostic procedures",
            "DISASTER_RECOVERY_PLAYBOOK.md – worst-case recovery",
            "Video walkthrough (10-part series)",
        ],
        effort_weeks=5,
        depends_on=["P0-M6"],
        risk="low",
    ),
    Milestone(
        id="P1-M4",
        title="API عمومی + SDK",
        description=(
            "REST API استاندارد با OpenAPI 3.1 برای automation, CI/CD "
            "integration, و توسعه‌دهندگان ثالث."
        ),
        deliverables=[
            "OpenAPI 3.1 spec برای تمام endpointها",
            "Python SDK (pip install dfim-client)",
            "Go SDK",
            "Terraform provider برای DFIM policy management",
        ],
        effort_weeks=8,
        depends_on=["P1-M2"],
        risk="medium",
    ),
]

PHASE_1 = Phase(
    ref="PHASE-1",
    title_fa="فاز ۱: محصول‌سازی و بسته‌بندی (Productization)",
    title_en="Phase 1: Productization & Packaging",
    timeline="هفته ۱۱ تا ۳۰ (۵ ماه)",
    goal="تبدیل DFIM از کدی که مهندس می‌فهمد به محصولی که اپراتور نصب می‌کند",
    milestones=PHASE1_MILESTONES,
    kpis=[
        "زمان نصب Windows: از ۳۰ دقیقه → زیر ۵ دقیقه",
        "زمان نصب Linux: از ۲۰ دقیقه → زیر ۲ دقیقه (apt install)",
        "تعداد API endpointها: 0 → ۲۰+",
        "تعداد SDK: ۰ → ۳ (Python, Go, Terraform)",
    ],
    exit_criteria=[
        "نصب و راه‌اندازی با یک دستور/کلیک ممکن باشد",
        "Central Management Dashboard عملیاتی باشد",
        "API عمومی با OpenAPI 3.1 مستند شده باشد",
    ],
)

# --- Phase 2: گواهی‌نامه و اعتبارسنجی صنعتی ------------------------------------

PHASE2_MILESTONES = [
    Milestone(
        id="P2-M1",
        title="FIPS 140-3 – ماژول رمزنگاری تاییدشده",
        description=(
            "جایگزینی RustCrypto p256 با یک ماژول تاییدشده FIPS 140-3. "
            "دو مسیر: OpenSSL 3.x FOM یا HSM خارجی (YubiHSM / NitroHSM)."
        ),
        deliverables=[
            "ماژول `dfim_core_engine/src/fips_crypto.rs` – wrapper دور FOM",
            "Fallback به RustCrypto در dev mode (غیر-production)",
            "تست سازگاری: خروجی FOM == خروجی RustCrypto برای تمام test vectors",
            "مستند `FIPS_140_3_INTEGRATION.md`",
        ],
        effort_weeks=8,
        depends_on=["P0-M5"],
        risk="critical",
    ),
    Milestone(
        id="P2-M2",
        title="Penetration Test مستقل – شخص ثالث",
        description=(
            "انجام penetration test توسط یک شرکت امنیتی معتبر (مانند NCC, "
            "Cure53, Trail of Bits) با scope کامل DFIM."
        ),
        deliverables=[
            "Scope document: تمام سطوح (UEFI, eBPF, CLI, TPM)",
            "Penetration test report از شرکت ثالث",
            "Remediation plan برای یافته‌ها",
            "Attestation letter (قابل اشتراک با مشتریان)",
        ],
        effort_weeks=6,
        depends_on=["P1-M1"],
        risk="high",
    ),
    Milestone(
        id="P2-M3",
        title="SOC 2 Type II + ISO 27001",
        description=(
            "گواهی SOC 2 Type II برای اعتماد SaaS و ISO 27001 برای "
            "انطباق با چارچوب امنیت اطلاعات."
        ),
        deliverables=[
            "SOC 2 Type II report (دوره ۶ ماهه)",
            "ISO 27001:2022 certification",
            "Policy framework: ۳۰+ control document",
        ],
        effort_weeks=14,
        depends_on=["P2-M1"],
        risk="high",
    ),
    Milestone(
        id="P2-M4",
        title="Common Criteria EAL 4+ (در صورت تقاضای دولت)",
        description=(
            "آماده‌سازی برای Common Criteria Evaluation Assurance Level 4+ "
            "برای بازارهای دولتی و دفاعی."
        ),
        deliverables=[
            "Security Target (ST) document",
            "Functional specification و TOE design",
            "Guidance documentation",
        ],
        effort_weeks=12,
        depends_on=["P2-M1", "P2-M2"],
        risk="critical",
    ),
]

PHASE_2 = Phase(
    ref="PHASE-2",
    title_fa="فاز ۲: گواهی‌نامه و اعتبارسنجی صنعتی (Certification)",
    title_en="Phase 2: Certification & Industrial Validation",
    timeline="هفته ۳۱ تا ۵۲ (۵.۵ ماه)",
    goal="کسب گواهی‌نامه‌های امنیتی ضروری برای ورود به بازارهای حساس: دولت، دفاع، بانکداری",
    milestones=PHASE2_MILESTONES,
    kpis=[
        "تعداد گواهی‌نامه‌ها: ۰ → ۴ (FIPS, SOC2, ISO27001, CC EAL4+)",
        "Penetration test findings: Critical=0, High=0 پس از remediation",
        "امتیاز ارزیابی کلی: 95% → 98%",
    ],
    exit_criteria=[
        "FIPS 140-3 validation letter دریافت شده باشد",
        "Penetration test با 0 critical و 0 high finding بسته شده باشد",
        "SOC 2 Type II و ISO 27001 صادر شده باشند",
    ],
)

# --- Phase 3: گسترش بازار و پلتفرم‌های جدید ------------------------------------

PHASE3_MILESTONES = [
    Milestone(
        id="P3-M1",
        title="Container & Kubernetes Integrity",
        description=(
            "گسترش DFIM به container images و runtime verification در "
            "Kubernetes. یکپارچگی image از build تا runtime."
        ),
        deliverables=[
            "DFIM admission controller (K8s webhook)",
            "Container runtime verification via eBPF در node",
            "Image signing integration (Cosign / Sigstore)",
            "OPA/Gatekeeper policy برای DFIM-verified images",
        ],
        effort_weeks=12,
        depends_on=["P1-M4"],
        risk="high",
    ),
    Milestone(
        id="P3-M2",
        title="ARM64 / AWS Graviton / Apple Silicon",
        description=(
            "پشتیبانی کامل از معماری ARM64: Linux eBPF روی Graviton، "
            "UEFI روی ARM servers، macOS Apple Silicon."
        ),
        deliverables=[
            "aarch64-unknown-linux-musl target build",
            "aarch64-unknown-uefi target برای ARM servers",
            "AWS Nitro Enclave attestation integration",
            "macOS Kernel Extension / System Extension برای integrity",
        ],
        effort_weeks=10,
        depends_on=["P0-M1"],
        risk="high",
    ),
    Milestone(
        id="P3-M3",
        title="Cloud-Native Attestation",
        description=(
            "پشتیبانی از AWS Nitro TPM, Azure vTPM, GCP Shielded VM. "
            "Attestation خودکار بدون دخالت اپراتور."
        ),
        deliverables=[
            "AWS Nitro TPM attestation provider",
            "Azure vTPM attestation provider",
            "GCP Shielded VM attestation provider",
            "Unified attestation API (abstraction over providers)",
        ],
        effort_weeks=8,
        depends_on=["P1-M2"],
        risk="medium",
    ),
    Milestone(
        id="P3-M4",
        title="SIEM Integrations (Splunk, ELK, Sentinel)",
        description=(
            "ارسال تلهمتری و alert مستقیماً به Splunk, Elastic, Microsoft "
            "Sentinel با فرمت‌های بومی هر پلتفرم."
        ),
        deliverables=[
            "Splunk TA (Technology Add-on) for DFIM",
            "Elastic Filebeat module for DFIM",
            "Microsoft Sentinel connector",
            "SOC playbook برای DFIM alerts",
        ],
        effort_weeks=6,
        depends_on=["P0-M7"],
        risk="medium",
    ),
]

PHASE_3 = Phase(
    ref="PHASE-3",
    title_fa="فاز ۳: گسترش بازار و پلتفرم‌های جدید (Expansion)",
    title_en="Phase 3: Market & Platform Expansion",
    timeline="هفته ۵۳ تا ۸۲ (۷.۵ ماه)",
    goal="گسترش از Windows/Linux محدود به Container, ARM, Cloud و تمام SIEMهای سازمانی",
    milestones=PHASE3_MILESTONES,
    kpis=[
        "پلتفرم‌های پشتیبانی‌شده: 2 (Win, Linux) → ۶+ (+ARM, macOS, K8s, Cloud)",
        "SIEM integrations: 1 (OTel) → ۴+ (+Splunk, ELK, Sentinel)",
        "تعداد endpointهای API: 20 → ۵۰+",
    ],
    exit_criteria=[
        "K8s admission controller در ۳ خوشه production تست شده باشد",
        "ARM64 build در CI به صورت خودکار تولید شود",
        "تمامی ۳ cloud provider attestation تایید شده باشند",
    ],
)

# --- Phase 4: اکوسیستم و انقلاب صنعتی ------------------------------------------

PHASE4_MILESTONES = [
    Milestone(
        id="P4-M1",
        title="Plugin API – سیاست‌های سفارشی",
        description=(
            "API باز برای نوشتن enforcement policyهای سفارشی توسط "
            "شرکت‌ها و سازمان‌ها. هر سازمان policy دلخواه خود را با Rust/WASM می‌نویسد."
        ),
        deliverables=[
            "DFIM Plugin SDK (Rust crate + WASM runtime)",
            "Policy marketplace / registry",
            "Sandboxed WASM execution در eBPF-side",
            "۳ نمونه policy آماده: banking, telecom, defense",
        ],
        effort_weeks=10,
        depends_on=["P1-M4", "P3-M1"],
        risk="high",
    ),
    Milestone(
        id="P4-M2",
        title="Open Source Community & Foundation",
        description=(
            "تاسیس DFIM Foundation (CNCF sandbox) یا پیوستن به یک "
            "بنیاد متن‌باز. جذب مشارکت‌کنندگان خارجی."
        ),
        deliverables=[
            "Governance model (MAINTAINERS.md, CONTRIBUTING.md)",
            "CNCF Sandbox application",
            "Community Discord/Slack",
            "Annual DFIMCon conference",
            "Certification program: DFIM Certified Operator",
        ],
        effort_weeks=8,
        depends_on=["P1-M4"],
        risk="medium",
    ),
    Milestone(
        id="P4-M3",
        title="DFIM-as-a-Service (SaaS)",
        description=(
            "سرویس ابری DFIM: مشتری بدون نصب، دستگاه‌های خود را از طریق "
            "agent متصل می‌کند و داشبورد مدیریت را در cloud دریافت می‌کند."
        ),
        deliverables=[
            "Multi-tenant cloud platform (K8s-based)",
            "Agent: سبک، auto-updating، TLS دائمی",
            "Billing: per-device/month",
            "SLA: 99.9% uptime",
        ],
        effort_weeks=16,
        depends_on=["P1-M2", "P2-M3", "P3-M3"],
        risk="critical",
    ),
    Milestone(
        id="P4-M4",
        title="Threat Intelligence Feed",
        description=(
            "فید اطلاعات تهدید مبتنی بر داده‌های جمع‌آوری‌شده از fleet. "
            "تشخیص حملات zero-day در firmware قبل از وقوع."
        ),
        deliverables=[
            "Anomaly detection ML pipeline روی integrity events",
            "Threat intelligence feed API",
            "Integration با MITRE ATT&CK",
            "Weekly threat digest برای مشترکین",
        ],
        effort_weeks=12,
        depends_on=["P4-M3"],
        risk="high",
    ),
]

PHASE_4 = Phase(
    ref="PHASE-4",
    title_fa="فاز ۴: اکوسیستم و انقلاب صنعتی (Ecosystem)",
    title_en="Phase 4: Ecosystem & Industrial Revolution",
    timeline="هفته ۸۳ تا ۱۰۶ (۶ ماه)",
    goal="تبدیل DFIM از یک محصول به یک اکوسیستم – استاندارد صنعتی Firmware Integrity",
    milestones=PHASE4_MILESTONES,
    kpis=[
        "تعداد مشارکت‌کنندگان خارجی: 0 → ۲۰+",
        "تعداد policy در marketplace: ۰ → ۱۰+",
        "تعداد دستگاه‌های تحت SaaS: ۰ → ۱۰٬۰۰۰+",
        "ARR از SaaS: $0 → $1M+",
    ],
    exit_criteria=[
        "CNCF Sandbox membership تایید شده باشد",
        "SaaS platform در production با 3 مشتری enterprise",
        "Plugin marketplace با حداقل ۵ policy عمومی",
        "Threat intelligence feed production-grade",
    ],
)

REVENUE_STREAMS = [
    RevenueStream(
        name_fa="مجوز Enterprise (On-Prem)",
        name_en="Enterprise License (On-Prem)",
        model="Per-node annual license + support",
        target_market="بانک‌ها، مخابرات، دولت، زیرساخت حیاتی",
        estimated_arr_range="$500K – $2M (Year 2)",
        moat="FIPS 140-3 + SOC2 + ISO27001 – رقبا این گواهی‌ها را ندارند",
    ),
    RevenueStream(
        name_fa="DFIM-as-a-Service (SaaS)",
        name_en="DFIM-as-a-Service (SaaS)",
        model="Per-device/month (tiered: $5-50/device/mo)",
        target_market="شرکت‌های متوسط، استارتاپ‌ها، cloud-native teams",
        estimated_arr_range="$1M – $5M (Year 3)",
        moat="Zero-install, always-updated, threat intelligence feed",
    ),
    RevenueStream(
        name_fa="Policy Marketplace",
        name_en="Policy Marketplace",
        model="Revenue share (70/30) on third-party policies",
        target_market="صنایع تخصصی (healthcare HIPAA, PCI-DSS, NERC-CIP)",
        estimated_arr_range="$100K – $500K (Year 3)",
        moat="Network effect – policies created by domain experts",
    ),
    RevenueStream(
        name_fa="گواهی و آموزش (Certification)",
        name_en="Training & Certification",
        model="Course fee + exam fee ($500-2000/person)",
        target_market="تیم‌های امنیتی سازمانی، MSSPها",
        estimated_arr_range="$200K – $500K (Year 2)",
        moat="First-mover in firmware integrity certification market",
    ),
]

ALL_PHASES = [PHASE_0, PHASE_1, PHASE_2, PHASE_3, PHASE_4]


def _build_roadmap() -> Roadmap:
    all_milestones: list[Milestone] = []
    for p in ALL_PHASES:
        all_milestones.extend(p.milestones)
    total_weeks = sum(m.effort_weeks for m in all_milestones)
    critical_path = [
        "P0-M1", "P0-M5", "P1-M1", "P2-M1", "P2-M2", "P2-M4",
        "P4-M3", "P4-M4"
    ]
    return Roadmap(
        version=ROADMAP_VERSION,
        generated_at=datetime.now(UTC).isoformat(),
        project_name="DFIM – Deterministic Firmware Integrity Matrix",
        vision=_VISION,
        phases=ALL_PHASES,
        revenue_streams=REVENUE_STREAMS,
        total_estimated_weeks=total_weeks,
        critical_path_ids=critical_path,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Output
# ═══════════════════════════════════════════════════════════════════════════


def _to_json(roadmap: Roadmap) -> str:
    def _serialize(o: Any) -> Any:
        if isinstance(o, (Roadmap, Phase, Milestone, RevenueStream)):
            return o.__dict__
        return str(o)
    return json.dumps(roadmap, default=_serialize, indent=2, ensure_ascii=False)


def _to_markdown(roadmap: Roadmap) -> str:
    lines: list[str] = []

    def w(s: str = "") -> None:
        lines.append(s)

    w("# پلن انقلابی DFIM – مسیر تبدیل به استاندارد صنعتی")
    w()
    w(f"**نسخه:** {roadmap.version} | **تاریخ تولید:** {roadmap.generated_at}")
    w(f"**مدت کل تخمینی:** {roadmap.total_estimated_weeks} هفته (~۲ سال)")
    w()
    w("---")
    w()
    w("## چشم‌انداز (Vision)")
    w()
    w(f"> {roadmap.vision}")
    w()
    w("## مسیر بحرانی (Critical Path)")
    w()
    w(" → ".join(roadmap.critical_path_ids))
    w()

    for phase in roadmap.phases:
        w("---")
        w()
        w(f"## {phase.ref}: {phase.title_fa}")
        w()
        w(f"**{phase.title_en}**")
        w()
        w(f"- **زمان‌بندی:** {phase.timeline}")
        w(f"- **هدف:** {phase.goal}")
        w()
        w("### KPIها")
        w()
        for kpi in phase.kpis:
            w(f"- {kpi}")
        w()
        w("### Milestoneها")
        w()
        w("| ID | عنوان | تلاش (هفته) | ریسک | پیش‌نیازها |")
        w("|----|-------|-------------|------|------------|")
        for m in phase.milestones:
            deps = ", ".join(m.depends_on) if m.depends_on else "—"
            w(f"| {m.id} | {m.title} | {m.effort_weeks} | {m.risk} | {deps} |")
        w()
        for m in phase.milestones:
            w(f"#### {m.id}: {m.title}")
            w()
            w(m.description)
            w()
            w("**Deliverables:**")
            for d in m.deliverables:
                w(f"- {d}")
            w()
        w("### معیارهای خروج از فاز")
        w()
        for ec in phase.exit_criteria:
            w(f"- {ec}")
        w()

    w("---")
    w()
    w("## مدل درآمدی (Revenue Streams)")
    w()
    w("| جریان درآمدی | مدل | بازار هدف | ARR تخمینی | مزیت رقابتی |")
    w("|--------------|-----|-----------|------------|-------------|")
    for rs in roadmap.revenue_streams:
        w(f"| {rs.name_fa} | {rs.model} | {rs.target_market} | {rs.estimated_arr_range} | {rs.moat} |")
    w()
    w("---")
    w()
    w("## نقشه راه خلاصه (Summary Timeline)")
    w()
    w("```")
    w("Phase 0: Gap Closure       ████████░░░░░░░░░░░░░░░░░░░░   Weeks  1-10  (10 w)")
    w("Phase 1: Productization     ░░░░░░░░░█████████████████░░░   Weeks 11-30  (20 w)")
    w("Phase 2: Certification       ░░░░░░░░░░░░░░░░░░░░░░░░████   Weeks 31-52  (22 w)")
    w("Phase 3: Market Expansion    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░   Weeks 53-82  (30 w)")
    w("Phase 4: Ecosystem           ░░░░░░░░░░░░░░░░░░░░░░░░░░░░   Weeks 83-106 (24 w)")
    w("```")
    w()
    w(f"**مجموع:** {roadmap.total_estimated_weeks} هفته (~۲ سال تا Stage-5 maturity)")
    w()

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════════


def validate_roadmap(roadmap: Roadmap) -> list[str]:
    """Validate internal consistency of the roadmap. Returns list of issues (empty = valid)."""
    errors: list[str] = []
    all_ids: set[str] = set()
    dep_graph: dict[str, set[str]] = {}

    for phase in roadmap.phases:
        for m in phase.milestones:
            if m.id in all_ids:
                errors.append(f"Duplicate milestone ID: {m.id}")
            all_ids.add(m.id)
            dep_graph[m.id] = set(m.depends_on)
            if m.effort_weeks <= 0:
                errors.append(f"{m.id}: effort_weeks must be > 0")
            if m.risk not in ("low", "medium", "high", "critical"):
                errors.append(f"{m.id}: invalid risk level '{m.risk}'")

    # Check all dependency references exist
    for m_id, deps in dep_graph.items():
        for dep in deps:
            if dep not in all_ids:
                errors.append(f"{m_id}: depends on non-existent milestone '{dep}'")

    # Check no cycles in dependency graph
    visited: set[str] = set()
    rec_stack: set[str] = set()

    def _has_cycle(node: str) -> bool:
        visited.add(node)
        rec_stack.add(node)
        for dep in dep_graph.get(node, set()):
            if dep not in visited:
                if _has_cycle(dep):
                    return True
            elif dep in rec_stack:
                return True
        rec_stack.discard(node)
        return False

    for m_id in all_ids:
        if m_id not in visited:
            if _has_cycle(m_id):
                errors.append(f"Cycle detected in dependency graph at {m_id}")
                break

    # Check total_estimated_weeks matches sum
    actual = sum(
        m.effort_weeks for p in roadmap.phases for m in p.milestones
    )
    if actual != roadmap.total_estimated_weeks:
        errors.append(
            f"total_estimated_weeks ({roadmap.total_estimated_weeks}) != "
            f"sum of milestone weeks ({actual})"
        )

    # Check critical path IDs all exist
    for cpid in roadmap.critical_path_ids:
        if cpid not in all_ids:
            errors.append(f"critical_path_ids references unknown milestone '{cpid}'")

    # Check KPIs and exit criteria
    for phase in roadmap.phases:
        if not phase.kpis:
            errors.append(f"{phase.ref}: no KPIs defined")
        if not phase.exit_criteria:
            errors.append(f"{phase.ref}: no exit criteria defined")
        if not phase.milestones:
            errors.append(f"{phase.ref}: no milestones defined")

    return errors


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(description="DFIM Revolutionary Development Roadmap")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--validate", action="store_true", help="Validate internal consistency only")
    parser.add_argument("--output", type=Path, help="Write output to file")
    args = parser.parse_args()

    roadmap = _build_roadmap()

    if args.validate:
        errors = validate_roadmap(roadmap)
        if errors:
            print("VALIDATION FAILED:")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        print("VALIDATION PASSED: roadmap is internally consistent.")
        return

    errors = validate_roadmap(roadmap)
    if errors:
        print("WARNING: Roadmap has validation issues:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)

    if args.json:
        output = _to_json(roadmap)
    else:
        output = _to_markdown(roadmap)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
