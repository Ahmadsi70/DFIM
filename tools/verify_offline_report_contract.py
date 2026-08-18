"""Enforces offline audit report generator controls for demo and air-gapped ops."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "tools/dfim_audit_report.py": {
        "parse_audit_file",
        "build_summary",
        "build_asset_statuses",
        "natural_language_summary",
        "load_asset_catalog",
        "render_html_report",
        "DFIM Integrity Health Report",
        "Executive summary",
        "Protected files",
        "dfim.policy.deny",
    },
    "tools/test_dfim_audit_report.py": {
        "test_build_asset_statuses_uses_latest_event_per_asset",
        "test_natural_language_summary_is_plain_english",
        "test_render_html_report_is_self_contained",
    },
    "test_environment/sample-telemetry/dfim_sample_audit.jsonl": {
        "verify_v1",
        "dfim.policy.deny",
        "recovery_v2",
    },
    "test_environment/sample-telemetry/assets.catalog.json": {
        "assets",
        "name",
        "host",
    },
    "docs/enterprise/OFFLINE_REPORT.md": {
        "dfim_audit_report.py",
        "Plain-English",
        "assets.catalog.json",
        "DFIM_TELEMETRY_OUT",
    },
    "test_environment/ops-stack/README.md": {
        "dfim_audit_report.py",
    },
    ".github/workflows/ci.yml": {
        "verify_offline_report_contract.py",
        "test_dfim_audit_report.py",
    },
}


def validate_required_controls() -> None:
    """Keeps offline reporting artifacts wired into CI and sample telemetry."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing offline report control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        missing = sorted(token for token in tokens if token.casefold() not in folded)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def validate_sample_report_generation() -> None:
    """Sample JSONL must produce a non-empty self-contained HTML report."""
    sample = ROOT / "test_environment" / "sample-telemetry" / "dfim_sample_audit.jsonl"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.html"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "dfim_audit_report.py"),
                "-i",
                str(sample),
                "-c",
                str(ROOT / "test_environment" / "sample-telemetry" / "assets.catalog.json"),
                "-o",
                str(out),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError(f"sample report generation failed: {result.stderr.strip()}")
        html = out.read_text(encoding="utf-8")
        if "https://" in html:
            raise ValueError("offline report must not reference external URLs")
        if "DFIM Integrity Health Report" not in html:
            raise ValueError("sample report missing title marker")
        if "Executive summary" not in html:
            raise ValueError("sample report missing executive summary section")


def main() -> int:
    """Runs the offline report contract as a dependency-free CI gate."""
    try:
        validate_required_controls()
        validate_sample_report_generation()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"OFFLINE-REPORT-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("OFFLINE-REPORT-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
