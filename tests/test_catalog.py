"""Unit tests for the container catalog generator and publish gate."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build_catalog = load_module("build_catalog", ROOT / "scripts" / "build-catalog.py")
verify_catalog = load_module("verify_catalog", ROOT / ".github" / "scripts" / "verify-catalog.py")


class CatalogParserTests(unittest.TestCase):
    def test_parse_tracks_format(self) -> None:
        vdata = {
            "last_updated": "2026-11-26",
            "debian_version": "13.8",
            "architectures": ["linux/amd64", "linux/arm64"],
            "signed": True,
            "slsa_provenance": True,
            "tracks": {
                "11.8": {
                    "version": "11.8.10",
                    "digest": "dgcosenza/mariadb@sha256:1111",
                    "ghcr_digest": "ghcr.io/dgcosenza/mariadb@sha256:1111",
                    "sizes_mb": {"amd64": "129.0", "arm64": "455.8"},
                    "trivy_fixable_critical_high": 0,
                    "grype_fixable_critical_high": 0,
                    "unfixed_cves": ["CVE-2026-0001", "CVE-2026-0002"],
                },
                "12.3": {
                    "version": "12.3.4",
                    "digest": "dgcosenza/mariadb@sha256:2222",
                    "ghcr_digest": "ghcr.io/dgcosenza/mariadb@sha256:2222",
                    "sizes_mb": {"amd64": "130.5", "arm64": "460.6"},
                    "trivy_fixable_critical_high": 0,
                    "grype_fixable_critical_high": 0,
                    "unfixed_cves": ["CVE-2026-0002", "CVE-2026-0003"],
                },
            },
        }
        parsed = build_catalog.parse_versions(vdata, "mariadb", "dgcosenza")
        self.assertEqual(parsed["upstream_version"], "11.8.10 / 12.3.4")
        self.assertEqual(parsed["build_date"], "2026-11-26")
        self.assertEqual(parsed["image_digest"], "dgcosenza/mariadb@sha256:2222")
        self.assertEqual(parsed["ghcr_digest"], "ghcr.io/dgcosenza/mariadb@sha256:2222")
        self.assertEqual(parsed["sizes_mb"], {"amd64": "130.5", "arm64": "460.6"})
        self.assertEqual(parsed["fixable_critical_high"], 0)
        self.assertEqual(parsed["unfixed_cve_count"], 3)

    def test_render_html_multi_hub_images(self) -> None:
        item = {
            "name": "azerothcore",
            "repo_name": "azerothcore-docker",
            "repo_url": "https://github.com/dgcosenza/azerothcore-docker",
            "description": "Hardened AzerothCore WotLK images",
            "image": "dgcosenza/ac-wotlk-worldserver",
            "hub_images": [
                "ac-wotlk-worldserver",
                "ac-wotlk-authserver",
                "ac-wotlk-db-import",
            ],
            "hub_url": "https://hub.docker.com/r/dgcosenza/ac-wotlk-worldserver",
            "ghcr_ref": "ghcr.io/dgcosenza/ac-wotlk-worldserver",
            "ghcr_url": "https://github.com/dgcosenza/azerothcore-docker/pkgs/container/ac-wotlk-worldserver",
            "upstream_name": "azerothcore",
            "upstream_version": "17.0.0-dev",
            "debian_version": "13.8",
            "base_os": "Debian 13.8",
            "base_image": "debian:trixie-slim",
            "architectures": ["linux/amd64"],
            "sizes_mb": {"amd64": "199.6"},
            "packaging_license": "MIT",
            "upstream_license": "GPL-2.0-only",
            "ci_status": "success",
            "ci_url": "https://github.com/dgcosenza/azerothcore-docker/actions/runs/1",
            "ci_updated": "2026-11-27T00:00:00Z",
            "ci_run_id": 1,
            "ci_rebuild_running": False,
            "build_date": "2026-11-27",
            "image_digest": "dgcosenza/ac-wotlk-worldserver@sha256:abc",
            "ghcr_digest": "ghcr.io/dgcosenza/ac-wotlk-worldserver@sha256:abc",
            "signed": True,
            "slsa_provenance": True,
            "release_provenance": True,
            "sbom": True,
            "release_tag": "17.0.0-dev-20261127",
            "release_url": "https://github.com/dgcosenza/azerothcore-docker/releases/tag/17.0.0-dev-20261127",
            "fixable_critical_high": 0,
            "unfixed_cve_count": 13,
            "scorecard_score": 7.3,
            "scorecard_date": "2026-11-26",
            "scorecard_url": "https://scorecard.dev/viewer/?uri=github.com/dgcosenza/azerothcore-docker",
            "bestpractices_id": 17155,
            "bestpractices_level": "passing",
            "bestpractices_url": "https://www.bestpractices.dev/en/projects/17155",
        }
        catalog = {
            "owner": "dgcosenza",
            "generated_at_utc": "2026-11-27T01:00:00Z",
            "summary": {
                "total_images": 1,
                "total_hub_images": 3,
                "passing_ci": 1,
                "zero_fixable_cves": 1,
                "signed_images": 1,
                "slsa_images": 1,
                "multi_arch_images": 0,
                "best_practices_passing": 1,
                "rebuilds_running": 0,
            },
            "images": [item],
        }
        rendered = build_catalog.render_html(catalog)
        self.assertIn("https://hub.docker.com/r/dgcosenza/ac-wotlk-worldserver", rendered)
        self.assertIn("https://hub.docker.com/r/dgcosenza/ac-wotlk-authserver", rendered)
        self.assertIn("https://hub.docker.com/r/dgcosenza/ac-wotlk-db-import", rendered)
        self.assertIn("Repositories (3 Hub Images)", rendered)


class VerifyCatalogGateTests(unittest.TestCase):
    def _sample_catalog(self, **overrides):
        img = {
            "name": "example",
            "ci_status": "success",
            "fixable_critical_high": 0,
            "unfixed_cve_count": 5,
            "scorecard_score": 7.3,
            "bestpractices_level": "passing",
            "build_date": "2026-11-26",
            "image_digest": "dgcosenza/example@sha256:1234",
        }
        img.update(overrides)
        return {
            "summary": {"total_images": 1, "total_hub_images": 1, "passing_ci": 1, "best_practices_passing": 1},
            "images": [img],
        }

    def test_verify_accepts_complete_site(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            (p / "catalog.json").write_text(json.dumps(self._sample_catalog()), encoding="utf-8")
            (p / "index.html").write_text("<html><body>passing Scorecard 7.3 Best Practices: passing</body></html>", encoding="utf-8")
            self.assertEqual(verify_catalog.verify_site(p, min_images=1), [])

    def test_verify_rejects_unregistered_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            cat = self._sample_catalog(name="duckdns", bestpractices_level="", bestpractices_url="")
            (p / "catalog.json").write_text(json.dumps(cat), encoding="utf-8")
            (p / "index.html").write_text("<html><body>passing Scorecard 7.1</body></html>", encoding="utf-8")
            errors = verify_catalog.verify_site(p, min_images=1)
            self.assertTrue(any("Best Practices" in e for e in errors), errors)

    def test_verify_rejects_na_and_missing_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            (p / "catalog.json").write_text(
                json.dumps(self._sample_catalog(scorecard_score=None, bestpractices_level="", build_date="")),
                encoding="utf-8",
            )
            (p / "index.html").write_text("<html><body>Scorecard N/A pending in progress</body></html>", encoding="utf-8")
            errs = verify_catalog.verify_site(p, min_images=1)
            joined = "\n".join(errs)
            self.assertIn("missing OpenSSF Scorecard score", joined)
            self.assertIn("missing OpenSSF Best Practices badge level", joined)
            self.assertIn("missing build_date", joined)
            self.assertIn("'N/A'", joined)
            self.assertIn("'pending'", joined)
            self.assertIn("'in progress'", joined)


if __name__ == "__main__":
    unittest.main()
