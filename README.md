# FNX Labs Container Image Catalog (`dgcosenza.github.io`)

[![Deploy Catalog to GitHub Pages](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/pages.yml/badge.svg)](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/pages.yml)
[![OpenSSF Scorecard Workflow](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/scorecard.yml/badge.svg)](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/scorecard.yml)
[![CodeQL SAST](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/codeql.yml/badge.svg)](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/codeql.yml)
[![Gitleaks Secret Scan](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/gitleaks.yml)
[![Public Content Check](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/public-check.yml/badge.svg)](https://github.com/dgcosenza/dgcosenza.github.io/actions/workflows/public-check.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dgcosenza/dgcosenza.github.io/badge)](https://scorecard.dev/viewer/?uri=github.com/dgcosenza/dgcosenza.github.io)

[![Live Catalog](https://img.shields.io/badge/catalog-live%20on%20GitHub%20Pages-0b1020?logo=githubpages&logoColor=white)](https://dgcosenza.github.io/)
[![Tracked Images](https://img.shields.io/badge/catalog-23%20repos%20%7C%2025%20Hub%20images-2496ED?logo=docker&logoColor=white)](https://dgcosenza.github.io/)
[![Trivy + Grype: 0 Fixable CVEs](https://img.shields.io/badge/Trivy%20%2B%20Grype-0%20fixable%20CVEs-brightgreen?logo=trivy&logoColor=white)](https://dgcosenza.github.io/)
[![Signed: Cosign OIDC](https://img.shields.io/badge/signed-Cosign%20OIDC-blueviolet)](https://dgcosenza.github.io/)
[![SLSA Build L3](https://img.shields.io/badge/SLSA-Build%20L3-brightgreen)](https://dgcosenza.github.io/)
[![SBOM: SPDX + CycloneDX](https://img.shields.io/badge/SBOM-SPDX%20%2B%20CycloneDX-0A7BBB?logo=spdx&logoColor=white)](https://dgcosenza.github.io/)

[![Renovate Enabled](https://img.shields.io/badge/renovate-enabled-1A1F6C?logo=renovate&logoColor=white)](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/renovate.json)
[![Dependabot Enabled](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/.github/dependabot.yml)
[![Last Commit](https://img.shields.io/github/last-commit/dgcosenza/dgcosenza.github.io?logo=github)](https://github.com/dgcosenza/dgcosenza.github.io/commits/main)
[![GitHub Issues](https://img.shields.io/github/issues/dgcosenza/dgcosenza.github.io?logo=github)](https://github.com/dgcosenza/dgcosenza.github.io/issues)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?logo=opensourceinitiative&logoColor=white)](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/LICENSE)
[![Maintainer](https://img.shields.io/badge/maintainer-FNX%20Labs-1d4ed8)](https://github.com/dgcosenza)

Central status, version, Cosign signature, SLSA Build L3 provenance, OpenSSF Scorecard, OpenSSF Best Practices, and vulnerability catalog for the hardened Debian 13 (`trixie-slim`) container images maintained by **Daniel G. Cosenza from FNX Labs**.

- **Live Catalog:** <https://dgcosenza.github.io/>
- **Machine-Readable JSON:** <https://dgcosenza.github.io/catalog.json>
- **Docker Hub Namespace:** <https://hub.docker.com/u/dgcosenza>

## What It Publishes

Every hour at minute **17** (and on every push to `main` or manual dispatch), [`.github/workflows/pages.yml`](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/.github/workflows/pages.yml) discovers every public `dgcosenza/*-docker` repository via the GitHub API and aggregates:

- **Resolved versions & base OS:** Upstream component versions, Debian release, architectures (`linux/amd64`, `linux/arm64`), and uncompressed image sizes from each repository's `versions.json`.
- **Daily CI build status:** Result of the latest *completed* `daily.yml` run on `main` (queued or in-progress rebuilds never overwrite final status), with direct workflow run links.
- **OpenSSF signals:** Live OpenSSF Scorecard score from `api.scorecard.dev` and OpenSSF Best Practices badge level from `bestpractices.dev`, with retries and last-published fallback if a third-party API is briefly unreachable.
- **Supply-chain attestations:** Cosign keyless OIDC signing status, SPDX & CycloneDX SBOM availability, SLSA Build L3 provenance status, identical Docker Hub + GHCR digests, and copy-ready verification commands.
- **Vulnerability posture:** Blocking Trivy + Grype all-severity fixable CVE gate (`0` fixable findings of any severity) and count of tracked upstream-unfixed advisories.
- **Licenses & governance:** Verified `packaging: MIT` and upstream SPDX licenses.

## Quality & Security Gates

- **Unit tests:** `python3 -m unittest discover -s tests -v` validates parser resilience and publish completeness checks.
- **Publish completeness gate:** `.github/scripts/verify-catalog.py` blocks deployment if any repository reports transient/partial states (`pending`, `in progress`, `N/A`), missing Scorecard/Best Practices scores, or missing build digests.
- **Static analysis & secret scanning:** CodeQL SAST (Python), Gitleaks full-history secret scan, OpenSSF Scorecard, and `.github/scripts/public-check.sh` run automatically on every push and pull request.

## Build Locally

```bash
GH_TOKEN="$(gh auth token)" python3 scripts/build-catalog.py --owner dgcosenza --out site
python3 .github/scripts/verify-catalog.py site
python3 -m http.server --directory site 8000
```

## License

Licensed under the [MIT License](https://github.com/dgcosenza/dgcosenza.github.io/blob/main/LICENSE) — copyright **Daniel G. Cosenza from FNX Labs**.
