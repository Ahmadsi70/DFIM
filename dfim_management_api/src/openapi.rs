//! Manual OpenAPI 3.1 spec serving (baked into binary).

use axum::Json;
use serde_json::json;

pub async fn openapi_spec() -> Json<serde_json::Value> {
    Json(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "DFIM Management API",
            "version": "1.0.0",
            "description": "DFIM Central Fleet Integrity Management — Phase 1 Productization (P1-M2/P1-M4)",
            "contact": { "name": "DFIM Engineering" },
            "license": { "name": "Apache 2.0" }
        },
        "servers": [{ "url": "/", "description": "Local" }],
        "paths": {
            "/health": {
                "get": { "summary": "Health check", "tags": ["Health"], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/fleet/summary": {
                "get": { "summary": "Fleet-wide integrity summary", "tags": ["Fleet"], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/assets": {
                "get": { "summary": "List enrolled assets", "tags": ["Assets"],
                    "parameters": [
                        { "name": "status", "in": "query", "schema": { "type": "string" } },
                        { "name": "host", "in": "query", "schema": { "type": "string" } },
                        { "name": "kind", "in": "query", "schema": { "type": "string" } },
                        { "name": "offset", "in": "query", "schema": { "type": "integer" } },
                        { "name": "limit", "in": "query", "schema": { "type": "integer" } }
                    ],
                    "responses": { "200": { "description": "Asset list" } }
                }
            },
            "/v1/assets/enroll": {
                "post": { "summary": "Enroll new protected asset", "tags": ["Assets"],
                    "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": {
                        "asset_id": { "type": "string" }, "display_name": { "type": "string" },
                        "asset_kind": { "type": "string" }, "host_name": { "type": "string" },
                        "policy_id": { "type": "string" }, "integrity_hash": { "type": "string" }
                    } } } } },
                    "responses": { "201": { "description": "Enrolled" }, "409": { "description": "Already enrolled" } }
                }
            },
            "/v1/assets/{asset_id}": {
                "get": { "summary": "Get asset detail", "tags": ["Assets"], "parameters": [{ "name": "asset_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "delete": { "summary": "Remove asset", "tags": ["Assets"], "parameters": [{ "name": "asset_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "Deleted" } } }
            },
            "/v1/assets/{asset_id}/verify": {
                "put": { "summary": "Verify asset integrity", "tags": ["Assets"], "parameters": [{ "name": "asset_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/policies": {
                "get": { "summary": "List enforcement policies", "tags": ["Policies"], "responses": { "200": { "description": "OK" } } },
                "post": { "summary": "Create policy", "tags": ["Policies"], "responses": { "201": { "description": "Created" } } }
            },
            "/v1/policies/{policy_id}": {
                "get": { "summary": "Get policy detail", "tags": ["Policies"], "parameters": [{ "name": "policy_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/nodes": {
                "get": { "summary": "List registered nodes", "tags": ["Nodes"], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/nodes/register": {
                "post": { "summary": "Register agent node", "tags": ["Nodes"], "responses": { "201": { "description": "Registered" } } }
            },
            "/v1/alerts": {
                "get": { "summary": "List security alerts", "tags": ["Alerts"], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/alerts/{alert_id}/acknowledge": {
                "post": { "summary": "Acknowledge alert", "tags": ["Alerts"], "parameters": [{ "name": "alert_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/siem/export": {
                "get": { "summary": "Export recent integrity alerts as SIEM events", "tags": ["SIEM"],
                    "parameters": [
                        { "name": "format", "in": "query", "schema": { "type": "string", "enum": ["ndjson", "splunk_hec", "elastic", "sentinel", "syslog"] }, "description": "Output format (default: ndjson)" },
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 5000 }, "description": "Max events to export (default: 500)" }
                    ],
                    "responses": { "200": { "description": "Serialized SIEM events; Content-Type varies by format" }, "400": { "description": "Unknown format" } }
                }
            },
            "/v1/telemetry": {
                "get": { "summary": "Query telemetry", "tags": ["Telemetry"], "responses": { "200": { "description": "OK" } } }
            },
            "/v1/telemetry/ingest": {
                "post": { "summary": "Ingest telemetry events", "tags": ["Telemetry"], "responses": { "200": { "description": "OK" } } }
            }
        },
        "tags": [
            { "name": "Health" }, { "name": "Fleet" }, { "name": "Assets" },
            { "name": "Policies" }, { "name": "Nodes" }, { "name": "Alerts" },
            { "name": "SIEM" }, { "name": "Telemetry" }
        ],
        "security": [{ "ApiKeyAuth": [] }],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
            }
        }
    }))
}
