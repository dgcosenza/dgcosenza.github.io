#!/usr/bin/env python3
"""Fail the build if the generated catalog would publish a transient, partial, or unknown state."""
from __future__ import annotations

import json
import pathlib
import re
import sys

MIN_IMAGES = 30
# Newly launched repositories awaiting interactive GitHub OAuth registration on bestpractices.dev.
# Remove each slug from this allowlist once its OpenSSF Best Practices badge is registered.
BESTPRACTICES_UNREGISTERED_ALLOWLIST = frozenset({
    "duckdns",
    "excalidraw",
    "fail2ban",
    "healthchecks",
    "rustdesk",
    "vscode",
    "wireguard",
})
FORBIDDEN_WORDS = ("pending", "in_progress", "in progress", "queued", "unknown")


def verify_site(site: pathlib.Path, min_images: int = MIN_IMAGES) -> list[str]:
    catalog = json.loads((site / "catalog.json").read_text(encoding="utf-8"))
    page = (site / "index.html").read_text(encoding="utf-8")
    errors: list[str] = []

    images = catalog.get("images") or []
    if len(images) < min_images:
        errors.append(f"catalog has only {len(images)} image(s), expected at least {min_images}")

    for img in images:
        name = img.get("name", "<unnamed>")
        if img.get("ci_status") not in ("success", "failure"):
            errors.append(
                f"{name}: ci_status is {img.get('ci_status')!r}, expected a completed-run verdict"
            )
        for key in ("fixable_critical_high", "unfixed_cve_count"):
            if img.get(key) is None:
                errors.append(f"{name}: {key} is null")
        if img.get("scorecard_score") is None:
            errors.append(f"{name}: missing OpenSSF Scorecard score")
        if not img.get("bestpractices_level") and name not in BESTPRACTICES_UNREGISTERED_ALLOWLIST:
            errors.append(f"{name}: missing OpenSSF Best Practices badge level")
        if not img.get("build_date"):
            errors.append(f"{name}: missing build_date")
        if not img.get("image_digest"):
            errors.append(f"{name}: missing image_digest")

    visible = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", page, flags=re.S)
    for word in FORBIDDEN_WORDS:
        if re.search(rf"\b{re.escape(word)}\b", visible, re.IGNORECASE):
            errors.append(f"index.html renders a transient state: {word!r}")
    if re.search(r"(?<![A-Za-z0-9/])N/A(?![A-Za-z0-9/])", visible):
        errors.append("index.html renders a partial/missing state: 'N/A'")

    return errors


def main(argv: list[str]) -> int:
    site = pathlib.Path(argv[1] if len(argv) > 1 else "site")
    errors = verify_site(site)
    catalog = json.loads((site / "catalog.json").read_text(encoding="utf-8"))
    for err in errors:
        print(f"::error::{err}")
    s = catalog["summary"]
    print(
        f"Catalog check: {s['passing_ci']}/{s['total_images']} passing CI "
        f"({s.get('total_hub_images', s['total_images'])} Hub images), "
        f"{s.get('best_practices_passing', 0)} Best Practices passing, {len(errors)} error(s)."
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
