# DFIM Project Governance

## Overview

DFIM (Deterministic Firmware Integrity Matrix) is an open-core project governed
by a maintainer council operating under a meritocratic, consensus-based model.
This document defines the project's governance structure, decision-making
processes, and community norms.

## Roles

### Maintainers
Maintainers have commit access to the repository and are responsible for:
- Reviewing and merging pull requests
- Triaging issues and security reports
- Steering technical direction
- Enforcing the Code of Conduct
- Releasing new versions

Current maintainers: See [MAINTAINERS.md](MAINTAINERS.md).

### Contributors
Anyone who submits a merged pull request is a contributor. Contributors may be
nominated to become maintainers by demonstrating sustained, high-quality
contributions over time.

### Community Members
Anyone using DFIM, reporting issues, participating in discussions, or
contributing documentation is a community member.

## Decision Making

### Consensus (default)
Routine decisions are made through lazy consensus: a proposal is considered
approved if no maintainer objects within 72 hours.

### Voting (for significant changes)
Significant changes (security model changes, major API breaks, governance
changes) require a supermajority vote (>66%) of active maintainers.

### Veto
Any maintainer may veto a change that they believe poses a security or safety
risk to users. A veto must be accompanied by a written explanation and a
proposed alternative.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
All participants are expected to uphold this code.

## Security Policy

See [SECURITY.md](../../SECURITY.md) for vulnerability reporting and
responsible disclosure procedures.

## License

All code is licensed under Apache 2.0. Documentation is licensed under
CC-BY-4.0.

## CNCF Sandbox

DFIM intends to apply to the Cloud Native Computing Foundation (CNCF) Sandbox.
This governance model is aligned with CNCF requirements.

## Amendments

This governance document may be amended by a supermajority vote of maintainers.
