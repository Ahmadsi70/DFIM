"""Unit tests for the offline DFIM audit JSONL report generator."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dfim_audit_report import (
    AssetStatus,
    build_asset_statuses,
    build_summary,
    load_asset_catalog,
    natural_language_summary,
    parse_audit_file,
    render_html_report,
)


SAMPLE_LINES = [
    {
        "schema_version": 1,
        "event_type": "verify_v1",
        "severity": "info",
        "outcome": "success",
        "timestamp_unix_ms": 1_700_000_000_000,
        "asset_id": "sha256:aa",
    },
    {
        "schema_version": 1,
        "event_type": "dfim.policy.deny",
        "severity": "error",
        "outcome": "failure",
        "timestamp_unix_ms": 1_700_000_060_000,
        "asset_id": "sha256:bb",
    },
    {
        "schema_version": 1,
        "event_type": "verify_v1",
        "severity": "error",
        "outcome": "failure",
        "timestamp_unix_ms": 1_700_000_120_000,
        "asset_id": "sha256:cc",
    },
]

CATALOG = {
    "assets": {
        "sha256:aa": {"name": "Primary boot image", "host": "pay-server-01"},
        "sha256:bb": {"name": "Kernel module", "host": "edge-02"},
        "sha256:cc": {"name": "Backup boot image", "host": "pay-server-02"},
    }
}


class AuditReportTests(unittest.TestCase):
    """Validates parsing, aggregation, and HTML emission for audit JSONL."""

    def test_parse_audit_file_skips_blank_and_malformed_lines(self) -> None:
        """Malformed lines must not abort report generation for valid records."""
        payload = "\n".join(
            [
                json.dumps(SAMPLE_LINES[0]),
                "",
                "{not-json",
                json.dumps(SAMPLE_LINES[1]),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            path.write_text(payload, encoding="utf-8")
            events = parse_audit_file(path)
        self.assertEqual(len(events), 2)

    def test_build_summary_counts_failures_and_alerts(self) -> None:
        """Summary must surface operational counts used in the offline dashboard."""
        summary = build_summary(SAMPLE_LINES)
        self.assertEqual(summary.total_events, 3)
        self.assertEqual(summary.by_event_type["verify_v1"], 2)
        self.assertEqual(summary.by_event_type["dfim.policy.deny"], 1)
        self.assertEqual(summary.by_outcome["failure"], 2)
        self.assertEqual(summary.alert_count, 2)

    def test_build_asset_statuses_uses_latest_event_per_asset(self) -> None:
        """Each enrolled asset must reflect its most recent integrity outcome."""
        statuses = build_asset_statuses(SAMPLE_LINES, CATALOG["assets"])
        by_id = {item.asset_id: item for item in statuses}
        self.assertEqual(by_id["sha256:aa"].status_label, "Healthy")
        self.assertEqual(by_id["sha256:bb"].status_label, "Execution blocked")
        self.assertEqual(by_id["sha256:cc"].status_label, "Unauthorized change")

    def test_natural_language_summary_is_plain_english(self) -> None:
        """Executive summary must be readable without security jargon."""
        statuses = build_asset_statuses(SAMPLE_LINES, CATALOG["assets"])
        text = natural_language_summary(statuses)
        self.assertIn("protected file", text.casefold())
        self.assertIn("healthy", text.casefold())
        self.assertIn("need attention", text.casefold())
        self.assertIn("does not scan the entire computer", text.casefold())

    def test_load_asset_catalog_from_json(self) -> None:
        """Optional catalog maps asset_id values to operator-friendly names."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "assets.json"
            path.write_text(json.dumps(CATALOG), encoding="utf-8")
            loaded = load_asset_catalog(path)
        self.assertEqual(loaded["sha256:aa"]["name"], "Primary boot image")

    def test_render_html_report_is_self_contained(self) -> None:
        """Generated HTML must work offline without external network dependencies."""
        summary = build_summary(SAMPLE_LINES)
        statuses = build_asset_statuses(SAMPLE_LINES, CATALOG["assets"])
        page = render_html_report(
            summary,
            SAMPLE_LINES,
            asset_statuses=statuses,
            executive_summary=natural_language_summary(statuses),
            source_label="sample.jsonl",
        )
        self.assertIn("DFIM Integrity Health Report", page)
        self.assertNotIn("https://", page)
        self.assertIn("Primary boot image", page)
        self.assertIn("Executive summary", page)
        self.assertIn("Protected files", page)


if __name__ == "__main__":
    unittest.main()
