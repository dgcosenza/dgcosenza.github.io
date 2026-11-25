# FNX Labs Container Image Catalog (`dgcosenza.github.io`)

[![Deploy Catalog to GitHub Pages](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/pages.yml/badge.svg)](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/pages.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dgcosenza/dgcosenza.github.io/badge)](https://scorecard.dev/viewer/?uri=github.com/dgcosenza/dgcosenza.github.io)

Central status, version, signature, and vulnerability catalog for the hardened Debian 13 (`trixie-slim`) container images maintained by **Daniel G. Cosenza from FNX Labs**.

- **Live Catalog:** <https://dgcosenza.github.io/>
- **Machine-Readable JSON:** <https://dgcosenza.github.io/catalog.json>

## What It Publishes

Every day at **06:45 UTC** (and on every push to `main` or manual dispatch), [`.github/workflows/pages.yml`](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/.github/workflows/pages.yml) discovers every public `dgcosenza/*-docker` repository via the GitHub API and aggregates:

- **Resolved versions & base OS:** Upstream component versions, Debian release, architectures (`linux/amd64`, `linux/arm64`), and image sizes from each repository's `versions.json`.
- **Daily CI build status:** Latest workflow run result and direct run link.
- **Supply-chain attestations:** Cosign keyless OIDC signing status, SPDX & CycloneDX SBOM availability, SLSA Build L3 provenance status, identical Docker Hub + GHCR digests, and copy-ready verification commands.
- **Vulnerability posture:** Blocking Trivy + Grype fixable Critical/High gate count (`0`) and count of tracked upstream-unfixed CVEs.
- **Licenses & governance:** Verified `packaging: MIT` and upstream SPDX licenses plus live OpenSSF Scorecard scores.

## Build Locally

```bash
GH_TOKEN="$(gh auth token)" python3 scripts/build-catalog.py --owner dgcosenza --out site
python3 -m http.server --directory site 8000
```

## License

Licensed under the [MIT License](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/LICENSE) — copyright **Daniel G. Cosenza from FNX Labs**.
