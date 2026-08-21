# DFIM Enterprise Telemetry

## Architecture and trust boundary

Phase 6 uses a two-layer design. The host CLI first appends one durable JSONL record and calls
`sync_all`; this local file is the security audit source of record. An OpenTelemetry Collector Contrib
agent then tails that file with `filelog`, parses JSON, and exports logs over OTLP. The CLI intentionally
does not embed an OpenTelemetry Rust dependency.

Set `DFIM_TELEMETRY_OUT` to enable auditing. When it is absent, telemetry is disabled. When it is set,
every `verify`, `verify-v2`, `provision`, `provision-v2`, and `recover-v2` success or failure must be recorded. Failure to open,
append, or synchronize the configured sink is reported as `[FAIL-CLOSED]` and a command can never
report success. A command whose security operation already failed remains failed and reports any
additional audit failure explicitly.

## JSONL schema version 1

Each line is one UTF-8 JSON object with these fields:

- `schema_version` (integer, required): always `1`.
- `event_type` (string, required): CLI operations use `verify_v1`, `verify_v2`, `provision_v1`,
  `provision_v2`, or `recovery_v2`. Linux enforcement may append SIEM-oriented types in the same file:
  `dfim.integrity.failure`, `dfim.metadata.corrupt`, or `dfim.policy.deny`.
- `severity` (string, required): `info` for success or `error` for failure.
- `outcome` (string, required): `success` or `failure`.
- `timestamp_unix_ms` (integer, required): host wall-clock milliseconds since the Unix epoch.
- `asset_id` (string, required): `sha256:` plus the lowercase SHA-256 digest of a domain-separated
  platform path encoding.
- `release_counter` (integer, optional): authenticated release metadata available after recovery.
- `merkle_root` (string, optional): lowercase 32-byte Merkle root available after successful
  verification, provision, or recovery.
- `dry_run` (boolean, optional): present and `true` when a provision command validated without writing a sidecar.

Field order and names are stable within schema version 1. Consumers must tolerate absent optional
fields and reject unknown schema versions rather than guessing their meaning.

## Redaction and confidentiality

The sink accepts typed fields only. It never serializes a raw path, command arguments, error text,
key ID, public/private key material, environment values, usernames, tokens, or other PII. `asset_id`
is a pseudonymous correlation identifier, not anonymization: low-entropy paths may be enumerable.
Restrict audit-file and backend access accordingly and never use the identifier as authentication.

## Collector operation

`test_environment/otel-collector/config.yaml` requires:

- `DFIM_TELEMETRY_OUT`: the same absolute JSONL path configured for the CLI.
- `DFIM_OTEL_STORAGE_DIR`: a persistent, access-controlled local directory for receiver offsets and
  exporter queue state.
- `DFIM_OTLP_ENDPOINT`: the organization OTLP gRPC endpoint. DNS, TLS trust, and any authentication
  extension or injected credentials are deployment responsibilities; no secret belongs in the file.

The pipeline orders `memory_limiter` before `batch`, persists the sending queue with `file_storage`,
and applies bounded exponential retry. Local append success does not prove backend delivery.
Operators must alert on Collector downtime, parse errors, refused logs, queue utilization above 60%,
permanent export failures, disk pressure, clock drift, and missing expected command events.

Run one writer per audit file or provide deployment-level writer serialization. Rotate only with a
method supported by the deployed `filelog` receiver, preserve unread files until offsets advance, and
test restart/replay behavior before production. Keep the local file and backend records for the
organization's incident-response and regulatory retention period; enforce immutable storage or
equivalent access controls, deletion holds, capacity limits, and documented disposal.

## Availability and maturity

The durable local layer remains authoritative during Collector or OTLP endpoint outages. Persistent
queues improve delivery across restarts but cannot guarantee delivery after disk loss, queue
exhaustion, permanent backend rejection, or operator deletion.

As of July 2026, the official OpenTelemetry Rust documentation classifies traces, metrics, and logs
as beta. The Collector Contrib `filelog` receiver is also beta. This maturity and potential breaking
changes are why DFIM keeps schema-versioned JSONL as the compatibility boundary and upgrades
Collector images only after configuration validation and replay qualification.

Official references:

- <https://opentelemetry.io/docs/collector/resiliency/>
- <https://opentelemetry.io/docs/collector/configuration/>
- <https://github.com/open-telemetry/opentelemetry-rust>
