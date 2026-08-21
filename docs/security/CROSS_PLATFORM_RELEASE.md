# DFIM Cross-Platform Attested Release (Phase 10)

## Published artifacts

Tagged releases (`v*`) produce three attested bundles from `.github/workflows/release.yml`:

| Artifact | Platform | Contents |
|----------|----------|----------|
| `dfim-linux-x86_64.tar.gz` | Linux x86_64 | `dfim-provisioner`, CycloneDX SBOM, LICENSE, checksums |
| `dfim-windows-x86_64.zip` | Windows x86_64 | `dfim-provisioner.exe`, `dfim_windows_uefi.efi`, LICENSE, checksums |
| `dfim-uefi-x86_64.tar.gz` | UEFI x86_64 | `dfim_windows_uefi.efi`, LICENSE, checksums |

All host CLI binaries are built with `--features production` (no evaluation-license gate).

## Consumer verification

Verify digest and GitHub attestation for each downloaded bundle:

```shell
# Linux
sha256sum --check RELEASE_SHA256SUMS
gh attestation verify dfim-linux-x86_64.tar.gz \
  --repo OWNER/DFIM \
  --signer-workflow OWNER/DFIM/.github/workflows/release.yml

# Windows (PowerShell)
Get-FileHash dfim-provisioner.exe -Algorithm SHA256
gh attestation verify dfim-windows-x86_64.zip \
  --repo OWNER/DFIM \
  --signer-workflow OWNER/DFIM/.github/workflows/release.yml

# UEFI firmware pipeline
sha256sum --check RELEASE_SHA256SUMS
gh attestation verify dfim-uefi-x86_64.tar.gz \
  --repo OWNER/DFIM \
  --signer-workflow OWNER/DFIM/.github/workflows/release.yml
```

Reject the release when:

- Checksums do not match `RELEASE_SHA256SUMS`.
- Attestation workflow identity or subject digest differs from expectation.
- Provenance `predicateType` is not `https://slsa.dev/provenance/v1`.

## Local packaging

```powershell
$env:DFIM_CRYPTO_KEY = "<org-controlled-material>"
.\package_windows_release.ps1
```

```bash
export DFIM_CRYPTO_KEY="<org-controlled-material>"
bash package_uefi_release.sh
```

## CI compile gate

Pull requests run `linux-ebpf-compile` with `DFIM_ALLOW_UNVERIFIED_BTF_FALLBACK=1` to prove the
eBPF probe and loader compile on every change. Runtime CO-RE offsets still require target-kernel BTF
on the deployment host.

## Relationship to platform qualification

Attested cross-platform **binaries** do not replace Linux runtime qualification (AT-01..04) or TPM
hardware evidence (AT-07). Treat attestation as supply-chain proof; treat adversarial acceptance as
runtime proof.
