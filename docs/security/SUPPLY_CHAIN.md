# DFIM Supply-Chain Security

DFIM release artifacts are built from a locked Cargo graph under a pinned Rust toolchain. Pull
requests cannot request OIDC tokens or create release attestations.

## Continuous integration gates

- `rust-toolchain.toml` pins Rust 1.91.1, rustfmt, Clippy, rust-src, and supported targets.
- `cargo test`, strict Clippy, formatting, Phase-0 policy, and the supply-chain contract are mandatory.
- `cargo-deny 0.19.9` rejects known advisories, yanked crates, wildcard registry dependencies,
  unapproved licenses, Git dependencies, and unknown registries.
- `cargo-cyclonedx 0.5.9` generates CycloneDX 1.5 with `SOURCE_DATE_EPOCH` for reproducible output.
- Dependabot separately tracks Cargo and GitHub Actions updates.

Duplicate transitive versions currently produce warnings rather than release failure because
RustCrypto 0.14 and existing SHA-2 consumers intentionally use different digest generations.
Advisories, licenses, wildcard dependencies, and source-policy violations remain blocking.

## Release identity and provenance

Tagged and manually dispatched releases run with only `contents: read`, `id-token: write`, and
`attestations: write`. The workflow:

1. Requires a repository secret for compile-time obfuscation material.
2. Builds with `Cargo.lock` via `cargo build --locked --release`.
3. Generates a deterministic CycloneDX SBOM and SHA-256 manifest.
4. Creates a normalized tar archive using a fixed epoch, ordering, owner, and group.
5. Uses `actions/attest@v4` to attach build provenance and a separate SBOM attestation.
6. Uploads the bundle, checksum manifest, and SBOM as immutable workflow artifacts.

Release secrets are not publisher-signing keys. GitHub OIDC supplies the short-lived identity used
for artifact attestations; DFIMBOOT private keys remain isolated in the organizational HSM/KMS.

## Consumer verification

Consumers must verify both the artifact digest and GitHub attestation before installation:

```shell
sha256sum --check RELEASE_SHA256SUMS
gh attestation verify dfim-linux-x86_64.tar.gz \
  --repo OWNER/DFIM \
  --signer-workflow OWNER/DFIM/.github/workflows/release.yml
```

Repository ownership alone is insufficient: production policy must constrain the signer workflow and
artifact digest. A copied attestation for another bundle or workflow is rejected.
