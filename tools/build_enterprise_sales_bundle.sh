#!/usr/bin/env bash
# Assemble enterprise tender / RFP evidence bundle from canonical docs.
set -euo pipefail

if grep -q $'\r' "$0" 2>/dev/null; then
  sed -i 's/\r$//' "$0"
  exec bash "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${DFIM_ENTERPRISE_BUNDLE:-${ROOT_DIR}/artifacts/enterprise-bundle}"
COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"

log() { printf '[ENTERPRISE-BUNDLE] %s\n' "$*"; }

DOCS=(
  docs/enterprise/RFP_RESPONSE_BUNDLE.md
  docs/enterprise/ENTERPRISE_SLA.md
  docs/enterprise/PILOT_CASE_STUDY_TEMPLATE.md
  docs/enterprise/OPS_TRAINING_CURRICULUM.md
  docs/enterprise/OFFLINE_REPORT.md
  docs/security/COMPLIANCE_MAPPING.md
  docs/security/PEN_TEST_SCOPE.md
  docs/security/CROSS_PLATFORM_RELEASE.md
  docs/security/RELEASE_MATURITY.md
  SECURITY.md
)

mkdir -p "${OUT_DIR}/docs"
for rel in "${DOCS[@]}"; do
  src="${ROOT_DIR}/${rel}"
  [[ -f "${src}" ]] || { echo "missing ${rel}" >&2; exit 1; }
  dest="${OUT_DIR}/docs/$(basename "${rel}")"
  cp "${src}" "${dest}"
done

cat >"${OUT_DIR}/BUNDLE_MANIFEST.json" <<EOF
{
  "schema_version": 1,
  "bundle_type": "enterprise_sales",
  "commit": "${COMMIT}",
  "generated_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "document_count": ${#DOCS[@]}
}
EOF

cat >"${OUT_DIR}/CHECKLIST.md" <<'EOF'
# Enterprise acceptance checklist

- [ ] Phase 0–12 CI contracts PASS on release commit
- [ ] Cross-platform attested bundles verified
- [ ] Platform qualification (AT-01..04, AT-07, AT-08 as applicable)
- [ ] Pen-test report — zero Critical/High open
- [ ] Pilot 90-day report completed
- [ ] HSM signing operational
- [ ] SOC integration live on JSONL
EOF

log "Bundle written to ${OUT_DIR}"
log "Manifest: ${OUT_DIR}/BUNDLE_MANIFEST.json"
