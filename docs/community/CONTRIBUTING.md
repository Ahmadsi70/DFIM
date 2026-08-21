# Contributing to DFIM

Thank you for your interest in contributing to DFIM!

## Developer Certificate of Origin (DCO)

All contributions must be signed off using the Developer Certificate of Origin.
Add `Signed-off-by: Your Name <email@example.com>` to your commit message.

By signing off, you certify that you have the right to submit the work under
the Apache 2.0 license.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

By making a contribution to this project, I certify that:
(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or
(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications...
```

## Pull Request Process

1. **Fork** the repository
2. Create a **feature branch** (`feat/description` or `fix/description`)
3. Write tests for your changes
4. Ensure all tests pass: `cargo test --workspace`
5. Format code: `cargo fmt --all -- --check`
6. Lint: `cargo clippy --workspace -- -D warnings`
7. Sign off your commits (`git commit -s`)
8. Open a **Pull Request** with a clear description
9. Wait for CI to pass and maintainer review

## Code Style

- Rust: Follow `rustfmt` and `clippy` defaults
- Python: Follow PEP 8, maximum line length 100
- Shell: Use `#!/bin/bash`, `set -euo pipefail`
- No `unsafe` Rust in `dfim_core_engine` (`#![deny(unsafe_code)]`)
- All public APIs must be documented with doc comments

## Testing Requirements

- Unit tests for all new functionality
- Integration tests for cross-crate interactions
- Kani proofs for safety-critical parsing (see `dfim_kani_proofs/`)
- Fuzz harnesses for parser modules (see `fuzz/`)
- Phase contract verification scripts (see `tools/verify_phase*.py`)

## Security Contributions

If you discover a security vulnerability, do NOT open a public issue.
Follow the process in [SECURITY.md](../SECURITY.md).

## Areas Needing Contribution

- **eBPF LSM hooks**: Expand Linux kernel enforcement surface
- **ARM64 UEFI**: Port Windows boot guard to ARM servers
- **WASM policies**: Build industry-specific policy plugins
- **Documentation**: Operator runbooks, tutorials, architecture diagrams
- **Testing**: Increase fuzz coverage, add property-based tests
- **SIEM connectors**: Add support for QRadar, ArcSight, Sumo Logic

## Communication

- GitHub Issues for bugs and feature requests
- GitHub Discussions for Q&A and design proposals
- Community Discord (coming soon)

## Recognition

All contributors are listed in the project's CONTRIBUTORS file and release
notes. Significant contributions may lead to maintainer nomination.
