#!/usr/bin/env python3
"""Build a self-contained offline HTML report from DFIM audit JSONL telemetry."""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ALERT_EVENT_TYPES = frozenset(
    {
        "dfim.policy.deny",
        "dfim.integrity.failure",
        "dfim.metadata.corrupt",
    }
)

VERIFY_EVENT_TYPES = frozenset({"verify_v1", "verify_v2"})


@dataclass(frozen=True)
class AuditSummary:
    """Aggregated audit metrics for the offline operations report."""

    total_events: int
    by_event_type: dict[str, int]
    by_outcome: dict[str, int]
    alert_count: int
    recent_alerts: list[dict[str, Any]]
    hourly_counts: list[tuple[str, int]]


@dataclass(frozen=True)
class AssetStatus:
    """Latest human-readable integrity state for one protected asset."""

    asset_id: str
    display_name: str
    host_label: str
    status_label: str
    status_class: str
    plain_message: str
    recommended_action: str
    last_checked: str
    last_event_type: str


def parse_audit_file(path: Path) -> list[dict[str, Any]]:
    """Parse JSONL audit records, skipping blank or malformed lines."""
    events: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        record.setdefault("_line", line_number)
        events.append(record)
    return events


def load_asset_catalog(path: Path | None) -> dict[str, dict[str, str]]:
    """Load optional asset_id to friendly-name mapping from JSON catalog."""
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    assets = payload.get("assets", {})
    if not isinstance(assets, dict):
        raise ValueError("catalog must contain an 'assets' object")
    normalized: dict[str, dict[str, str]] = {}
    for asset_id, meta in assets.items():
        if not isinstance(meta, dict):
            continue
        normalized[str(asset_id)] = {
            "name": str(meta.get("name", "Protected file")),
            "host": str(meta.get("host", "Unknown host")),
        }
    return normalized


def build_summary(events: list[dict[str, Any]]) -> AuditSummary:
    """Compute dashboard counters and alert rows from parsed audit events."""
    by_event_type = Counter(str(event.get("event_type", "unknown")) for event in events)
    by_outcome = Counter(str(event.get("outcome", "unknown")) for event in events)

    alerts = [
        event
        for event in events
        if event.get("outcome") == "failure"
        or str(event.get("event_type", "")) in ALERT_EVENT_TYPES
    ]
    alerts.sort(key=lambda event: int(event.get("timestamp_unix_ms", 0)), reverse=True)

    hour_counter: Counter[str] = Counter()
    for event in events:
        timestamp_ms = event.get("timestamp_unix_ms")
        if not isinstance(timestamp_ms, int):
            continue
        hour_label = datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:00")
        hour_counter[hour_label] += 1

    hourly_counts = sorted(hour_counter.items())
    return AuditSummary(
        total_events=len(events),
        by_event_type=dict(by_event_type),
        by_outcome=dict(by_outcome),
        alert_count=len(alerts),
        recent_alerts=alerts[:20],
        hourly_counts=hourly_counts,
    )


def _format_timestamp(timestamp_ms: Any) -> str:
    """Render a human-readable UTC timestamp for report tables."""
    if not isinstance(timestamp_ms, int):
        return "Unknown time"
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _resolve_display_name(asset_id: str, catalog: dict[str, dict[str, str]]) -> tuple[str, str]:
    """Map pseudonymous asset_id to operator-friendly labels."""
    meta = catalog.get(asset_id, {})
    short_id = asset_id.removeprefix("sha256:")
    short_id = short_id[:12] + "…" if len(short_id) > 12 else short_id
    name = meta.get("name") or f"Protected file ({short_id})"
    host = meta.get("host") or "Unknown host"
    return name, host


def _interpret_latest_event(event: dict[str, Any]) -> tuple[str, str, str, str]:
    """Translate the latest audit event into plain-English status fields."""
    event_type = str(event.get("event_type", "unknown"))
    outcome = str(event.get("outcome", "unknown"))

    if event_type in VERIFY_EVENT_TYPES and outcome == "success":
        return (
            "Healthy",
            "ok",
            "This file matches the authorized version recorded by your organization.",
            "No action required.",
        )
    if event_type in VERIFY_EVENT_TYPES and outcome == "failure":
        return (
            "Unauthorized change",
            "bad",
            "The file content no longer matches the authorized version.",
            "Contact your security or platform team. Restore only from an approved source.",
        )
    if event_type == "dfim.policy.deny":
        return (
            "Execution blocked",
            "bad",
            "The system blocked execution because this protected file was changed.",
            "Investigate the change and run an authorized recovery if needed.",
        )
    if event_type == "dfim.integrity.failure":
        return (
            "Content tampered",
            "bad",
            "Runtime integrity checking detected unauthorized content changes.",
            "Contact your security team immediately.",
        )
    if event_type == "dfim.metadata.corrupt":
        return (
            "Metadata invalid",
            "bad",
            "The integrity sidecar or signed metadata appears corrupted or forged.",
            "Do not trust this file until metadata is rebuilt from an approved source.",
        )
    if event_type == "recovery_v2" and outcome == "success":
        return (
            "Restored",
            "ok",
            "This file was successfully restored from an approved recovery source.",
            "Verify scheduled monitoring continues as normal.",
        )
    if event_type.startswith("provision") and outcome == "success":
        return (
            "Enrolled",
            "warn",
            "This file was enrolled for protection. A full verify has not been recorded yet.",
            "Run a verify check to confirm the baseline.",
        )
    if outcome == "failure":
        return (
            "Needs attention",
            "bad",
            "An integrity-related operation failed for this protected file.",
            "Review the audit trail with your platform team.",
        )
    return (
        "Informational",
        "warn",
        "An integrity event was recorded for this protected file.",
        "Review details with your platform team if unexpected.",
    )


def build_asset_statuses(
    events: list[dict[str, Any]],
    catalog: dict[str, dict[str, str]],
) -> list[AssetStatus]:
    """Derive one latest-status row per asset_id for the protected-files table."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        asset_id = str(event.get("asset_id", ""))
        if not asset_id:
            continue
        grouped.setdefault(asset_id, []).append(event)

    statuses: list[AssetStatus] = []
    for asset_id, asset_events in grouped.items():
        latest = max(asset_events, key=lambda item: int(item.get("timestamp_unix_ms", 0)))
        display_name, host_label = _resolve_display_name(asset_id, catalog)
        status_label, status_class, plain_message, recommended_action = _interpret_latest_event(latest)
        statuses.append(
            AssetStatus(
                asset_id=asset_id,
                display_name=display_name,
                host_label=host_label,
                status_label=status_label,
                status_class=status_class,
                plain_message=plain_message,
                recommended_action=recommended_action,
                last_checked=_format_timestamp(latest.get("timestamp_unix_ms")),
                last_event_type=str(latest.get("event_type", "unknown")),
            )
        )

    order = {"bad": 0, "warn": 1, "ok": 2}
    statuses.sort(key=lambda item: (order.get(item.status_class, 9), item.display_name.casefold()))
    return statuses


def natural_language_summary(statuses: list[AssetStatus]) -> str:
    """Build an executive paragraph readable by non-technical stakeholders."""
    total = len(statuses)
    healthy = sum(1 for item in statuses if item.status_class == "ok")
    attention = total - healthy

    if total == 0:
        return (
            "No protected files appear in this audit file yet. "
            "This report covers only files explicitly enrolled in DFIM — it does not scan the entire computer."
        )

    if attention == 0:
        lead = (
            f"All {healthy} protected file{'s' if healthy != 1 else ''} checked in this report are healthy "
            "and match the authorized versions recorded by your organization."
        )
    elif healthy == 0:
        lead = (
            f"All {attention} protected file{'s' if attention != 1 else ''} in this report need attention. "
            "Review the items below and contact your security or platform team."
        )
    else:
        lead = (
            f"Out of {total} protected files in this report, {healthy} are healthy and {attention} need attention."
        )

    return (
        f"{lead} "
        "This report covers only files explicitly enrolled in DFIM — it does not scan the entire computer "
        "and it is not an antivirus scan."
    )


def _bar_rows(items: dict[str, int], total: int) -> str:
    """Render simple horizontal bars without external chart libraries."""
    if not items:
        return "<p class=\"muted\">No events recorded.</p>"
    peak = max(items.values()) or 1
    rows: list[str] = []
    for label, count in sorted(items.items(), key=lambda pair: (-pair[1], pair[0])):
        width = max(4, int((count / peak) * 100))
        rows.append(
            "<div class=\"bar-row\">"
            f"<span class=\"bar-label\">{html.escape(label)}</span>"
            f"<span class=\"bar-track\"><span class=\"bar-fill\" style=\"width:{width}%\"></span></span>"
            f"<span class=\"bar-value\">{count}</span>"
            "</div>"
        )
    return "".join(rows)


def _status_badge(status_class: str, label: str) -> str:
    """Render a colored status pill for asset rows."""
    return f'<span class="badge {html.escape(status_class)}">{html.escape(label)}</span>'


def render_html_report(
    summary: AuditSummary,
    events: list[dict[str, Any]],
    *,
    asset_statuses: list[AssetStatus],
    executive_summary: str,
    source_label: str,
) -> str:
    """Emit a single HTML file that opens offline without CDN dependencies."""
    generated_at = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    success_count = summary.by_outcome.get("success", 0)
    failure_count = summary.by_outcome.get("failure", 0)
    verify_count = summary.by_event_type.get("verify_v1", 0) + summary.by_event_type.get(
        "verify_v2", 0
    )
    deny_count = summary.by_event_type.get("dfim.policy.deny", 0)
    recovery_count = summary.by_event_type.get("recovery_v2", 0)

    healthy_count = sum(1 for item in asset_statuses if item.status_class == "ok")
    attention_count = len(asset_statuses) - healthy_count
    overall_class = "ok" if attention_count == 0 and asset_statuses else ("bad" if attention_count else "warn")
    overall_label = (
        "All protected files healthy"
        if attention_count == 0 and asset_statuses
        else ("Attention required" if attention_count else "No enrolled files in audit")
    )

    asset_rows: list[str] = []
    for item in asset_statuses:
        asset_rows.append(
            "<tr>"
            f"<td><strong>{html.escape(item.display_name)}</strong><br>"
            f"<span class=\"muted\">{html.escape(item.host_label)}</span></td>"
            f"<td>{_status_badge(item.status_class, item.status_label)}</td>"
            f"<td>{html.escape(item.plain_message)}</td>"
            f"<td>{html.escape(item.last_checked)}</td>"
            f"<td>{html.escape(item.recommended_action)}</td>"
            "</tr>"
        )
    if not asset_rows:
        asset_rows.append(
            "<tr><td colspan=\"5\" class=\"muted\">"
            "No protected-file events were found. Enroll files and run verify checks to populate this section."
            "</td></tr>"
        )

    alert_rows = []
    for event in summary.recent_alerts:
        asset_id = str(event.get("asset_id", "—"))
        name, _ = _resolve_display_name(asset_id, {})
        alert_rows.append(
            "<tr>"
            f"<td>{html.escape(_format_timestamp(event.get('timestamp_unix_ms')))}</td>"
            f"<td>{html.escape(name)}</td>"
            f"<td>{html.escape(str(event.get('event_type', 'unknown')))}</td>"
            f"<td>{html.escape(str(event.get('outcome', 'unknown')))}</td>"
            "</tr>"
        )
    if not alert_rows:
        alert_rows.append("<tr><td colspan=\"4\" class=\"muted\">No alerts in this audit file.</td></tr>")

    hourly_html = _bar_rows(dict(summary.hourly_counts), summary.total_events or 1)
    event_type_html = _bar_rows(summary.by_event_type, summary.total_events or 1)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DFIM Integrity Health Report</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #0f172a;
      --panel: #1e293b;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --warn: #f97316;
      --ok: #22c55e;
      --bad: #ef4444;
    }}
    @media (prefers-color-scheme: light) {{
      :root {{
        --bg: #f8fafc;
        --panel: #ffffff;
        --text: #0f172a;
        --muted: #64748b;
      }}
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
    h1 {{ margin: 0 0 8px; font-size: 1.8rem; }}
    h2 {{ margin-top: 0; font-size: 1.1rem; }}
    .meta {{ color: var(--muted); margin-bottom: 24px; }}
    .hero {{
      background: var(--panel);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
      border-left: 6px solid var(--accent);
    }}
    .hero.bad {{ border-left-color: var(--bad); }}
    .hero.ok {{ border-left-color: var(--ok); }}
    .hero.warn {{ border-left-color: var(--warn); }}
    .hero .headline {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 8px; }}
    .hero .summary {{ font-size: 1rem; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .card {{
      background: var(--panel);
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 1px 2px rgba(0,0,0,.15);
    }}
    .card .label {{ color: var(--muted); font-size: .85rem; }}
    .card .value {{ font-size: 1.8rem; font-weight: 700; }}
    .ok {{ color: var(--ok); }}
    .warn {{ color: var(--warn); }}
    .bad {{ color: var(--bad); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .panel {{
      background: var(--panel);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 16px;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
    th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid rgba(148,163,184,.25); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .badge {{
      display: inline-block;
      padding: 2px 10px;
      border-radius: 999px;
      font-size: .82rem;
      font-weight: 600;
      background: rgba(148,163,184,.2);
    }}
    .badge.ok {{ background: rgba(34,197,94,.18); color: var(--ok); }}
    .badge.warn {{ background: rgba(249,115,22,.18); color: var(--warn); }}
    .badge.bad {{ background: rgba(239,68,68,.18); color: var(--bad); }}
    .bar-row {{
      display: grid;
      grid-template-columns: 140px 1fr 40px;
      gap: 8px;
      align-items: center;
      margin-bottom: 8px;
    }}
    .bar-label {{ font-size: .85rem; }}
    .bar-track {{
      background: rgba(148,163,184,.2);
      border-radius: 999px;
      height: 10px;
      overflow: hidden;
    }}
    .bar-fill {{
      display: block;
      height: 100%;
      background: linear-gradient(90deg, var(--accent), #818cf8);
    }}
    .bar-value {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .muted {{ color: var(--muted); }}
    footer {{ margin-top: 32px; color: var(--muted); font-size: .85rem; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>DFIM Integrity Health Report</h1>
    <p class="meta">Source: {html.escape(source_label)} · Generated: {generated_at} · Audit events: {summary.total_events}</p>

    <section class="hero {overall_class}">
      <div class="headline">{html.escape(overall_label)}</div>
      <p class="summary"><strong>Executive summary:</strong> {html.escape(executive_summary)}</p>
    </section>

    <div class="cards">
      <div class="card"><div class="label">Protected files</div><div class="value">{len(asset_statuses)}</div></div>
      <div class="card"><div class="label">Healthy</div><div class="value ok">{healthy_count}</div></div>
      <div class="card"><div class="label">Need attention</div><div class="value bad">{attention_count}</div></div>
      <div class="card"><div class="label">Checks recorded</div><div class="value">{verify_count}</div></div>
      <div class="card"><div class="label">Execution blocks</div><div class="value warn">{deny_count}</div></div>
      <div class="card"><div class="label">Recoveries</div><div class="value">{recovery_count}</div></div>
    </div>

    <section class="panel">
      <h2>Protected files</h2>
      <table>
        <thead>
          <tr><th>File</th><th>Status</th><th>What this means</th><th>Last checked</th><th>Suggested action</th></tr>
        </thead>
        <tbody>
          {''.join(asset_rows)}
        </tbody>
      </table>
    </section>

    <div class="grid">
      <section class="panel">
        <h2>Activity by type (technical)</h2>
        {event_type_html}
      </section>
      <section class="panel">
        <h2>Hourly activity (UTC)</h2>
        {hourly_html}
      </section>
    </div>

    <section class="panel">
      <h2>Recent alerts (technical)</h2>
      <table>
        <thead>
          <tr><th>Time</th><th>File</th><th>Event</th><th>Outcome</th></tr>
        </thead>
        <tbody>
          {''.join(alert_rows)}
        </tbody>
      </table>
    </section>

    <footer>
      This report covers only files explicitly enrolled in DFIM. It verifies integrity against authorized
      baselines; it does not scan the entire computer and it is not an antivirus product. For live monitoring,
      forward audit JSONL to your SOC or Grafana ops stack.
    </footer>
  </div>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    """CLI entry: read JSONL audit file and write a standalone HTML report."""
    parser = argparse.ArgumentParser(description="Generate an offline HTML report from DFIM audit JSONL.")
    parser.add_argument("--input", "-i", required=True, type=Path, help="Path to DFIM_TELEMETRY_OUT JSONL file")
    parser.add_argument("--output", "-o", required=True, type=Path, help="Output HTML path")
    parser.add_argument(
        "--catalog",
        "-c",
        type=Path,
        help="Optional JSON catalog mapping asset_id to friendly file names",
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"DFIM-REPORT: FAIL: input not found: {args.input}", file=sys.stderr)
        return 1

    try:
        catalog = load_asset_catalog(args.catalog)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as error:
        print(f"DFIM-REPORT: FAIL: invalid catalog: {error}", file=sys.stderr)
        return 1

    events = parse_audit_file(args.input)
    summary = build_summary(events)
    asset_statuses = build_asset_statuses(events, catalog)
    executive_summary = natural_language_summary(asset_statuses)
    report = render_html_report(
        summary,
        events,
        asset_statuses=asset_statuses,
        executive_summary=executive_summary,
        source_label=str(args.input),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    healthy = sum(1 for item in asset_statuses if item.status_class == "ok")
    print(
        f"DFIM-REPORT: wrote {args.output} "
        f"({len(asset_statuses)} protected files, {healthy} healthy, {summary.alert_count} alerts)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
