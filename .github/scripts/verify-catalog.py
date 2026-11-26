#!/usr/bin/env python3
"""Fail the build if the generated catalog would publish a transient or unknown state."""
from __future__ import annotations

import json
import pathlib
import re
import sys

site = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "site")
catalog = json.loads((site / "catalog.json").read_text(encoding="utf-8"))
page = (site / "index.html").read_text(encoding="utf-8")
errors: list[str] = []

for img in catalog["images"]:
    name = img["name"]
    if img.get("ci_status") not in ("success", "failure"):
        errors.append(f"{name}: ci_status is {img.get('ci_status')!r}, expected a completed-run verdict")
    for key in ("fixable_critical_high", "unfixed_cve_count"):
        if img.get(key) is None:
            errors.append(f"{name}: {key} is null")
    if img.get("scorecard_score") is None:
        print(f"::warning::{name}: no OpenSSF Scorecard result published yet")
    if not img.get("bestpractices_level"):
        print(f"::warning::{name}: no OpenSSF Best Practices badge found")

visible = re.sub(r"<[^>]+>", " ", page)
for word in ("pending", "in_progress", "in progress", "queued", "unknown"):
    if re.search(rf"\b{re.escape(word)}\b", visible, re.IGNORECASE):
        errors.append(f"index.html renders a transient state: {word!r}")

for err in errors:
    print(f"::error::{err}")
s = catalog["summary"]
print(
    f"Catalog check: {s['passing_ci']}/{s['total_images']} passing CI, "
    f"{s.get('best_practices_passing', 0)} Best Practices passing, {len(errors)} error(s)."
)
sys.exit(1 if errors else 0)
