#!/usr/bin/env python3
"""
DFIM Client SDK — Python client for the DFIM Central Management API.

Phase 1 – P1-M4 Productization

Install:  pip install requests
Usage:
    from dfim_client import DfimClient
    c = DfimClient("http://localhost:3000")
    c.fleet_summary()
    c.enroll_asset("sha256:abc", "nginx", "WebServer", "node-01")
    c.verify_asset("sha256:abc", "sha256:abc")
"""

from __future__ import annotations

import json
import time
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

# ═══════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════

@dataclass
class FleetSummary:
    total_assets: int = 0
    healthy: int = 0
    tampered: int = 0
    blocked: int = 0
    pending: int = 0
    total_nodes: int = 0
    total_policies: int = 0
    active_alerts: int = 0
    integrity_coverage_pct: float = 0.0

    @classmethod
    def from_dict(cls, d: dict) -> FleetSummary:
        return cls(**{k: d.get(k, 0) for k in cls.__dataclass_fields__})


@dataclass
class Asset:
    asset_id: str = ""
    display_name: str = ""
    asset_kind: str = ""
    host_name: str = ""
    status: str = "unknown"
    integrity_hash: Optional[str] = None
    last_verified: str = ""
    enrolled_at: str = ""
    policy_id: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> Asset:
        return cls(
            asset_id=d.get("asset_id", ""),
            display_name=d.get("display_name", ""),
            asset_kind=d.get("asset_kind", ""),
            host_name=d.get("host_name", ""),
            status=d.get("status", "unknown"),
            integrity_hash=d.get("integrity_hash"),
            last_verified=d.get("last_verified", ""),
            enrolled_at=d.get("enrolled_at", ""),
            policy_id=d.get("policy_id"),
        )


@dataclass
class Policy:
    policy_id: str = ""
    name: str = ""
    version: int = 1
    enforcement_mode: str = "protected-scope"
    controls: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        return cls(
            policy_id=d.get("policy_id", ""),
            name=d.get("name", ""),
            version=d.get("version", 1),
            enforcement_mode=d.get("enforcement_mode", "protected-scope"),
            controls=d.get("controls", []),
        )


@dataclass
class Alert:
    alert_id: str = ""
    severity: str = "info"
    asset_id: str = ""
    message: str = ""
    timestamp: str = ""
    acknowledged: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> Alert:
        return cls(**{k: d.get(k, cls.__dataclass_fields__[k].default) for k in cls.__dataclass_fields__})


@dataclass
class NodeInfo:
    node_id: str = ""
    host_name: str = ""
    platform: str = ""
    status: str = "online"
    dfim_version: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> NodeInfo:
        return cls(**{k: d.get(k, "") for k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════
# Client
# ═══════════════════════════════════════════════════════════════════

class DfimClient:
    """DFIM Management API client."""

    def __init__(self, base_url: str = "http://localhost:3000", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(self, method: str, path: str, body: Any = None) -> dict | list:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        req = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(req, timeout=10) as resp:
                raw = resp.read().decode()
                if raw:
                    return json.loads(raw)
                return {}
        except URLError as e:
            raise DfimApiError(f"{method} {path} failed: {e}") from e

    # Health ──────────────────────────────────────────────────────────
    def health(self) -> dict:
        return self._request("GET", "/health")

    # Fleet ───────────────────────────────────────────────────────────
    def fleet_summary(self) -> FleetSummary:
        return FleetSummary.from_dict(self._request("GET", "/v1/fleet/summary"))

    # Assets ──────────────────────────────────────────────────────────
    def list_assets(self, status: str = "", host: str = "", kind: str = "", limit: int = 100) -> list[Asset]:
        params = []
        if status: params.append(f"status={status}")
        if host: params.append(f"host={host}")
        if kind: params.append(f"kind={kind}")
        if limit != 100: params.append(f"limit={limit}")
        qs = "?" + "&".join(params) if params else ""
        data = self._request("GET", f"/v1/assets{qs}")
        return [Asset.from_dict(a) for a in data]

    def get_asset(self, asset_id: str) -> Asset:
        return Asset.from_dict(self._request("GET", f"/v1/assets/{asset_id}"))

    def enroll_asset(self, asset_id: str, display_name: str, asset_kind: str,
                     host_name: str, policy_id: str = "", integrity_hash: str = "") -> Asset:
        body = {"asset_id": asset_id, "display_name": display_name,
                "asset_kind": asset_kind, "host_name": host_name}
        if policy_id: body["policy_id"] = policy_id
        if integrity_hash: body["integrity_hash"] = integrity_hash
        return Asset.from_dict(self._request("POST", "/v1/assets/enroll", body))

    def verify_asset(self, asset_id: str, integrity_hash: str = "") -> Asset:
        body = {}
        if integrity_hash: body["integrity_hash"] = integrity_hash
        return Asset.from_dict(self._request("PUT", f"/v1/assets/{asset_id}/verify", body))

    def delete_asset(self, asset_id: str) -> dict:
        return self._request("DELETE", f"/v1/assets/{asset_id}")

    # Policies ────────────────────────────────────────────────────────
    def list_policies(self) -> list[Policy]:
        return [Policy.from_dict(p) for p in self._request("GET", "/v1/policies")]

    def get_policy(self, policy_id: str) -> Policy:
        return Policy.from_dict(self._request("GET", f"/v1/policies/{policy_id}"))

    def create_policy(self, policy_id: str, name: str) -> Policy:
        return Policy.from_dict(self._request("POST", "/v1/policies",
                                              {"policy_id": policy_id, "name": name}))

    # Nodes ───────────────────────────────────────────────────────────
    def list_nodes(self) -> list[NodeInfo]:
        return [NodeInfo.from_dict(n) for n in self._request("GET", "/v1/nodes")]

    def register_node(self, host_name: str, platform: str = "linux",
                      node_id: str = "", version: str = "0.1.0") -> NodeInfo:
        body = {"host_name": host_name, "platform": platform, "version": version}
        if node_id: body["node_id"] = node_id
        return NodeInfo.from_dict(self._request("POST", "/v1/nodes/register", body))

    # Alerts ──────────────────────────────────────────────────────────
    def list_alerts(self, limit: int = 100) -> list[Alert]:
        data = self._request("GET", f"/v1/alerts?limit={limit}")
        return [Alert.from_dict(a) for a in data]

    def acknowledge_alert(self, alert_id: str) -> Alert:
        return Alert.from_dict(self._request("POST", f"/v1/alerts/{alert_id}/acknowledge"))

    # Telemetry ───────────────────────────────────────────────────────
    def list_telemetry(self, limit: int = 100) -> list[dict]:
        return self._request("GET", f"/v1/telemetry?limit={limit}")

    def ingest_telemetry(self, events: list[dict]) -> dict:
        return self._request("POST", "/v1/telemetry/ingest", events)


class DfimApiError(Exception):
    pass


# ═══════════════════════════════════════════════════════════════════
# CLI (for testing)
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    client = DfimClient()

    print("DFIM Client SDK — Integration Test")
    print("=" * 40)

    h = client.health()
    print(f"Health: {h['status']} | {h['asset_count']} assets | uptime {h['uptime_seconds']}s")

    fs = client.fleet_summary()
    print(f"Fleet: {fs.total_assets} total, {fs.healthy} healthy, {fs.tampered} tampered")

    assets = client.list_assets()
    print(f"Assets: {len(assets)} enrolled")

    policies = client.list_policies()
    print(f"Policies: {len(policies)} configured")

    # Enroll test
    a = client.enroll_asset("sdk-test", "SDK Test", "Tool", "sdk-host", integrity_hash="sha256:sdk-test")
    print(f"Enrolled: {a.display_name} ({a.status})")

    # Verify
    a = client.verify_asset("sdk-test", "sha256:sdk-test")
    print(f"Verified OK: {a.status}")

    a = client.verify_asset("sdk-test", "sha256:wrong")
    print(f"Verified WRONG: {a.status}")

    alerts = client.list_alerts()
    print(f"Alerts: {len(alerts)} active")

    # Cleanup
    client.delete_asset("sdk-test")
    print("Deleted test asset")

    print("=" * 40)
    print("SDK integration test PASSED")
