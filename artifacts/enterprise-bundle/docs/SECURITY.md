# DFIM Security

DFIM is an integrity enforcement system for explicitly enrolled firmware and executable assets. Its
security design baseline is defined by:

- `security/phase0-policy.json` — machine-readable approved decisions.
- `docs/security/THREAT_MODEL.md` — assets, trust boundaries, adversaries, and threats.
- `docs/security/ENFORCEMENT_POLICY.md` — normative enforcement behavior.
- `docs/security/ADVERSARIAL_ACCEPTANCE.md` — release-blocking security tests.
- `docs/security/DFIMBOOT_V2.md` — signed boot metadata and rollback-baseline contract.
- `docs/security/REMOTE_ATTESTATION.md` — TPM quote and remote-verifier contract.
- `docs/security/SUPPLY_CHAIN.md` — dependency, SBOM, release, and provenance gates.
- `docs/security/RECOVERY.md` — authenticated, rollback-safe recovery and soak gates.
- `docs/security/TELEMETRY.md` — redacted durable JSONL audit and OpenTelemetry delivery contract.
- `docs/security/PRODUCTION_PACKAGING.md` — production builds, HSM signing custody, and host gate bypass policy.
- `docs/security/CROSS_PLATFORM_RELEASE.md` — attested Linux, Windows, and UEFI release verification.
- `docs/security/LINUX_QUALIFY.md` — AT-01..AT-04 lab qualification and SIEM evidence bundle.
- `docs/security/PLATFORM_QUALIFICATION.md` — AT-07 swtpm CI and AT-08 destructive qualification.
- `docs/security/UEFI_CAPSULE_RECOVERY.md` — authenticated FMP capsule recovery runbook.
- `docs/security/COMPLIANCE_MAPPING.md` — ISO 27001 and telecom procurement mapping.
- `docs/security/PEN_TEST_SCOPE.md` — external assessment scope and severity policy.
- `docs/enterprise/RFP_RESPONSE_BUNDLE.md` — twenty-question tender response baseline.
- `docs/enterprise/ENTERPRISE_SLA.md` — support tiers and performance SLA template.
- `docs/security/RELEASE_MATURITY.md` — Phase 7–12 release and audit gates.

## Current security status

The repository is at an enterprise-hardening stage, not an independently certified production release.
The following limitations are security-relevant:

- Linux protected-scope policy delegates current-content appraisal to IMA; runtime adversarial
  acceptance on the deployment kernel remains required.
- DFIMBOOT v1 remains legacy-only. Production UEFI uses DFIMBOOT v2 with P-256 signatures and a
  firmware time-authenticated rollback baseline.
- The RustCrypto P-256 implementation is not by itself a FIPS 140-3 validated cryptographic module;
  regulated deployments require an approved module and HSM/KMS release-signing integration.
- Tagged Linux, Windows, and UEFI bundles receive GitHub attestations via `release.yml`; consumers
  must verify digests and provenance per `CROSS_PLATFORM_RELEASE.md`.
- DFIMSTAT v1 uses an unkeyed checksum; it detects accidental or isolated modification but does not
  establish publisher authenticity.
- TPM support produces nonce-bound ECC quotes for PCR 0/2/4/7/14. Production AK enrollment still
  requires EK-certificate validation or an equivalent controlled asset-registration channel.
- Production use must not rely on the evaluation-license mechanism as a root of trust.
- Host recovery authenticates and re-verifies each replacement and has a bounded CI soak profile;
  destructive power-loss and UEFI authenticated-capsule qualification remain platform gates.
- Enterprise telemetry is opt-in through `DFIM_TELEMETRY_OUT` and fail-closed after configuration.
  Durable local JSONL is authoritative; OpenTelemetry Collector delivery remains dependent on
  operator-managed disk capacity, retention, TLS/authentication, monitoring, and beta component
  qualification.
- Phase 7–12 add bounded libFuzzer coverage, CodeQL, Kani proofs, cross-platform attested releases,
  platform qualification gates, and enterprise sales/compliance artifacts as repository release gates.
  Runtime platform qualification, hardware TPM execution, independent pen-test closure, and formal
  certification remain outside automated CI claims.

## Vulnerability reporting

Report suspected vulnerabilities through the deploying organization's private security channel. Include:

- Affected commit/release and platform.
- Reproduction steps and required privileges.
- Security boundary crossed and expected versus observed result.
- Minimal logs with credentials, keys, tokens, personal data, and production asset identifiers removed.

Do not publish working bypasses, private signing material, TPM authorization values, or production
sidecars before coordinated remediation is complete.

## Release security gate

A release described as enterprise-ready must have passing adversarial acceptance evidence, signed
artifacts, SBOM and provenance, no unresolved Critical/High findings, and an independently reviewed
cryptographic and platform threat model.
