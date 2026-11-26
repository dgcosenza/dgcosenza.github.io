#!/usr/bin/env python3
"""Build the public FNX Labs container image catalog site (HTML + JSON)."""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import html
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "dgcosenza-container-catalog/1.0"
API_BASE = "https://api.github.com"
SCORECARD_BASE = "https://api.scorecard.dev/projects/github.com"


def load_forbidden_regex() -> re.Pattern[str] | None:
    script = pathlib.Path(".github/scripts/public-check.sh")
    if script.exists():
        for line in script.read_text(encoding="utf-8").splitlines():
            if line.startswith("FORBIDDEN='") and line.endswith("'"):
                return re.compile(line[len("FORBIDDEN='") : -1], re.IGNORECASE)
    return None


FORBIDDEN_RE = load_forbidden_regex()


def sanitize_text(val: str | None) -> str:
    if not val:
        return ""
    if FORBIDDEN_RE and FORBIDDEN_RE.search(val):
        return ""
    return val.strip()


def http_get_json(url: str, token: str | None = None, timeout: int = 15) -> Any | None:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token and url.startswith(API_BASE):
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def list_docker_repos(owner: str, token: str | None) -> list[dict[str, Any]]:
    repos: list[dict[str, Any]] = []
    page = 1
    while True:
        data = http_get_json(
            f"{API_BASE}/users/{owner}/repos?type=public&per_page=100&page={page}&sort=full_name",
            token=token,
        )
        if not isinstance(data, list) or not data:
            break
        for r in data:
            name = r.get("name") or ""
            if name.endswith("-docker") and not r.get("archived") and not r.get("private"):
                repos.append(r)
        if len(data) < 100:
            break
        page += 1
    repos.sort(key=lambda r: r["name"])
    return repos


def parse_versions(vdata: dict[str, Any] | None, slug: str, owner: str) -> dict[str, Any]:
    if not isinstance(vdata, dict):
        return {}

    # Multi-series format (e.g., mariadb-docker with series: {"11.8": ..., "12.3": ...})
    if isinstance(vdata.get("series"), dict) and vdata["series"]:
        series_map: dict[str, Any] = vdata["series"]
        vers = [str(s.get("version") or k) for k, s in series_map.items() if isinstance(s, dict)]
        fixable = 0
        unfixed_union: set[str] = set()
        digest = ""
        ghcr_digest = ""
        for _k, s in series_map.items():
            if not isinstance(s, dict):
                continue
            fixable = max(
                fixable,
                int(s.get("trivy_fixable_critical_high", s.get("fixable_critical_high", 0)) or 0),
                int(s.get("grype_fixable_critical_high", 0) or 0),
            )
            for c in s.get("unfixed_cves") or []:
                unfixed_union.add(str(c))
            if s.get("digest"):
                digest = str(s["digest"])
            if s.get("ghcr_digest"):
                ghcr_digest = str(s["ghcr_digest"])
        return {
            "image": str(vdata.get("image") or f"{owner}/{slug}"),
            "upstream_name": str(vdata.get("upstream_name") or ""),
            "upstream_version": " / ".join(vers),
            "upstream_license": str(vdata.get("upstream_license") or ""),
            "packaging_license": str(vdata.get("packaging_license") or "MIT"),
            "debian_version": str(vdata.get("debian_version") or ""),
            "architectures": list(vdata.get("architectures") or []),
            "sizes_mb": {},
            "signed": bool(vdata.get("signed", False)),
            "slsa_provenance": bool(vdata.get("slsa_provenance", False)),
            "build_date": str(vdata.get("build_date") or ""),
            "image_digest": digest,
            "ghcr_digest": ghcr_digest,
            "fixable_critical_high": fixable,
            "unfixed_cve_count": len(unfixed_union),
        }

    unfixed = vdata.get("unfixed_cves") or []
    if not isinstance(unfixed, list):
        unfixed = []
    fixable_raw = vdata.get("fixable_critical_high")
    if fixable_raw is None:
        fixable_raw = max(
            int(vdata.get("trivy_fixable_critical_high", 0) or 0),
            int(vdata.get("grype_fixable_critical_high", 0) or 0),
        )
    digest = str(vdata.get("image_digest") or vdata.get("last_digest") or "")
    ghcr_digest = str(vdata.get("ghcr_digest") or "")
    return {
        "image": str(vdata.get("image") or f"{owner}/{slug}"),
        "upstream_name": str(vdata.get("upstream_name") or ""),
        "upstream_version": str(vdata.get("upstream_version") or vdata.get("version") or ""),
        "upstream_license": str(vdata.get("upstream_license") or ""),
        "packaging_license": str(vdata.get("packaging_license") or "MIT"),
        "debian_version": str(vdata.get("debian_version") or ""),
        "architectures": list(vdata.get("architectures") or []),
        "sizes_mb": dict(vdata.get("sizes_mb") or {}),
        "signed": bool(vdata.get("signed", False)),
        "slsa_provenance": bool(vdata.get("slsa_provenance", False)),
        "build_date": str(vdata.get("build_date") or ""),
        "image_digest": digest,
        "ghcr_digest": ghcr_digest,
        "fixable_critical_high": int(fixable_raw or 0),
        "unfixed_cve_count": len(unfixed),
    }


def fetch_repo_record(owner: str, repo: dict[str, Any], token: str | None) -> dict[str, Any]:
    name = repo["name"]
    slug = name[: -len("-docker")]
    full_name = f"{owner}/{name}"

    # 1. versions.json
    vdata = None
    vresp = http_get_json(f"{API_BASE}/repos/{full_name}/contents/versions.json", token=token)
    if isinstance(vresp, dict) and vresp.get("content"):
        try:
            vdata = json.loads(base64.b64decode(vresp["content"]).decode("utf-8"))
        except Exception:
            vdata = None
    parsed = parse_versions(vdata, slug, owner)

    # 2. Upstream license fallback from README badge if not in versions.json
    upstream_license = parsed.get("upstream_license") or ""
    if not upstream_license:
        rresp = http_get_json(f"{API_BASE}/repos/{full_name}/readme", token=token)
        if isinstance(rresp, dict) and rresp.get("content"):
            try:
                readme_txt = base64.b64decode(rresp["content"]).decode("utf-8", errors="ignore")
                m = re.search(r"img\.shields\.io/badge/upstream-([A-Za-z0-9_.+-]+?)-(?:green|blue|orange|yellow|brightgreen|informational|lightgrey)", readme_txt)
                if m:
                    upstream_license = m.group(1).replace("--", "-")
            except Exception:
                pass

    # 3. Latest daily.yml workflow run
    ci_status = "unknown"
    ci_url = f"https://github.com/{full_name}/actions"
    ci_updated = ""
    runs_resp = http_get_json(
        f"{API_BASE}/repos/{full_name}/actions/workflows/daily.yml/runs?branch=main&per_page=1",
        token=token,
    )
    runs = (runs_resp or {}).get("workflow_runs") if isinstance(runs_resp, dict) else None
    if not runs:
        runs_resp = http_get_json(
            f"{API_BASE}/repos/{full_name}/actions/runs?branch=main&per_page=1",
            token=token,
        )
        runs = (runs_resp or {}).get("workflow_runs") if isinstance(runs_resp, dict) else None
    if isinstance(runs, list) and runs:
        latest_run = runs[0]
        ci_status = latest_run.get("conclusion") or latest_run.get("status") or "unknown"
        ci_url = latest_run.get("html_url") or ci_url
        ci_updated = latest_run.get("updated_at") or ""

    # 4. Latest GitHub Release + signed/provenance/SBOM assets
    rel_tag = ""
    rel_url = f"https://github.com/{full_name}/releases"
    rel_signed = False
    rel_provenance = False
    rel_sbom = False
    rel = http_get_json(f"{API_BASE}/repos/{full_name}/releases/latest", token=token)
    if isinstance(rel, dict) and rel.get("tag_name"):
        rel_tag = str(rel["tag_name"])
        rel_url = str(rel.get("html_url") or rel_url)
        asset_names = [str(a.get("name") or "") for a in (rel.get("assets") or [])]
        rel_signed = any(a.endswith((".sigstore.json", ".sig", ".asc", ".bundle")) for a in asset_names)
        rel_provenance = any(a.endswith(".intoto.jsonl") for a in asset_names)
        rel_sbom = any(".spdx." in a or ".cdx." in a for a in asset_names)

    # 5. OpenSSF Scorecard score
    sc_score: float | None = None
    sc = http_get_json(f"{SCORECARD_BASE}/{full_name}", token=None, timeout=10)
    if isinstance(sc, dict) and isinstance(sc.get("score"), (int, float)):
        sc_score = round(float(sc["score"]), 1)

    image_ref = parsed.get("image") or f"{owner}/{slug}"
    hub_slug = image_ref.split("/", 1)[1] if "/" in image_ref else slug
    pkg_lic = (repo.get("license") or {}).get("spdx_id") or parsed.get("packaging_license") or "MIT"

    return {
        "name": slug,
        "repo_name": name,
        "repo_url": repo["html_url"],
        "description": sanitize_text(repo.get("description")),
        "image": image_ref,
        "hub_url": f"https://hub.docker.com/r/{owner}/{hub_slug}",
        "ghcr_ref": f"ghcr.io/{owner}/{hub_slug}",
        "ghcr_url": f"https://github.com/{full_name}/pkgs/container/{hub_slug}",
        "upstream_name": sanitize_text(parsed.get("upstream_name")),
        "upstream_version": sanitize_text(parsed.get("upstream_version")) or (rel_tag.split("-202")[0] if rel_tag else ""),
        "debian_version": sanitize_text(parsed.get("debian_version")),
        "architectures": parsed.get("architectures") or [],
        "sizes_mb": parsed.get("sizes_mb") or {},
        "packaging_license": sanitize_text(pkg_lic),
        "upstream_license": sanitize_text(upstream_license),
        "ci_status": ci_status,
        "ci_url": ci_url,
        "ci_updated": ci_updated,
        "build_date": sanitize_text(parsed.get("build_date")),
        "image_digest": sanitize_text(parsed.get("image_digest")),
        "ghcr_digest": sanitize_text(parsed.get("ghcr_digest")),
        "signed": bool(parsed.get("signed") or rel_signed),
        "slsa_provenance": bool(parsed.get("slsa_provenance") or rel_provenance),
        "release_provenance": rel_provenance,
        "sbom": bool(parsed.get("signed") or rel_sbom),
        "release_tag": sanitize_text(rel_tag),
        "release_url": rel_url,
        "fixable_critical_high": parsed.get("fixable_critical_high") if "fixable_critical_high" in parsed else None,
        "unfixed_cve_count": parsed.get("unfixed_cve_count") if "unfixed_cve_count" in parsed else None,
        "scorecard_score": sc_score,
        "scorecard_url": f"https://scorecard.dev/viewer/?uri=github.com/{full_name}",
    }


def render_html(catalog: dict[str, Any]) -> str:
    items = catalog["images"]
    summary = catalog["summary"]
    gen_at = html.escape(catalog["generated_at_utc"])

    rows_html: list[str] = []
    for idx, item in enumerate(items):
        name_esc = html.escape(item["name"])
        desc_esc = html.escape(item["description"] or "Hardened Debian 13 container image")
        repo_url = html.escape(item["repo_url"])
        hub_url = html.escape(item["hub_url"])
        ghcr_url = html.escape(item["ghcr_url"])
        rel_url = html.escape(item["release_url"])
        ci_url = html.escape(item["ci_url"])
        sc_url = html.escape(item["scorecard_url"])

        ver_esc = html.escape(item["upstream_version"] or "—")
        deb_esc = f"Debian {html.escape(item['debian_version'])}" if item["debian_version"] else "Debian 13"
        arches = item["architectures"] or []
        arch_short = " | ".join(a.replace("linux/", "") for a in arches) if arches else "amd64"
        multi = len(arches) >= 2

        ci = item["ci_status"]
        if ci == "success":
            ci_badge = f'<a class="pill ok" href="{ci_url}" target="_blank" rel="noopener">passing</a>'
        elif ci in ("in_progress", "queued"):
            ci_badge = f'<a class="pill warn" href="{ci_url}" target="_blank" rel="noopener">{html.escape(ci)}</a>'
        elif ci == "failure":
            ci_badge = f'<a class="pill fail" href="{ci_url}" target="_blank" rel="noopener">failing</a>'
        else:
            ci_badge = f'<a class="pill muted" href="{ci_url}" target="_blank" rel="noopener">{html.escape(ci)}</a>'

        fixable = item["fixable_critical_high"]
        unfixed = item["unfixed_cve_count"]
        if fixable is None:
            cve_html = '<span class="pill muted">pending scan</span>'
            zero_fix = False
        elif fixable == 0:
            zero_fix = True
            unfix_note = f'<span class="sub">{unfixed} upstream-unfixed</span>' if unfixed is not None else ""
            cve_html = f'<span class="pill ok">0 fixable C/H</span>{unfix_note}'
        else:
            zero_fix = False
            cve_html = f'<span class="pill fail">{fixable} fixable C/H</span>'

        sc_parts: list[str] = []
        if item["signed"]:
            sc_parts.append('<span class="pill accent">Cosign OIDC</span>')
        if item["slsa_provenance"]:
            sc_parts.append('<span class="pill ok">SLSA L3</span>')
        if item["sbom"]:
            sc_parts.append('<span class="pill info">SBOM</span>')
        if item["ghcr_digest"]:
            sc_parts.append('<span class="pill info">GHCR + Hub</span>')
        if not sc_parts:
            sc_parts.append('<span class="pill muted">in progress</span>')
        supply_html = " ".join(sc_parts)

        sc_val = item["scorecard_score"]
        if sc_val is not None:
            sc_cls = "ok" if sc_val >= 8.0 else ("info" if sc_val >= 6.5 else "warn")
            scorecard_html = f'<a class="pill {sc_cls}" href="{sc_url}" target="_blank" rel="noopener">{sc_val:.1f} / 10</a>'
        else:
            scorecard_html = f'<a class="pill muted" href="{sc_url}" target="_blank" rel="noopener">pending</a>'

        pkg_lic = html.escape(item["packaging_license"] or "MIT")
        up_lic = html.escape(item["upstream_license"] or "see repo")
        lic_html = f'<span class="pill info">pkg: {pkg_lic}</span> <span class="pill muted">up: {up_lic}</span>'

        digest_ref = item["ghcr_digest"] or item["image_digest"] or f"{item['ghcr_ref']}:latest"
        verify_cmd = (
            f"cosign verify \\\n"
            f'  --certificate-identity-regexp="^https://github\\.com/dgcosenza/{item["repo_name"]}/\\.github/workflows/daily\\.yml@refs/heads/main$" \\\n'
            f'  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \\\n'
            f"  {digest_ref}"
        )
        attest_cmd = f"gh attestation verify oci://{digest_ref} --owner dgcosenza"
        pull_cmd = f"docker pull {item['image_digest'] or (item['image'] + ':latest')}"

        sizes = item.get("sizes_mb") or {}
        size_line = ", ".join(f"{html.escape(str(k))}: {html.escape(str(v))} MB" for k, v in sizes.items())
        size_sub = f'<span class="sub">{size_line}</span>' if size_line else ""
        bdate = html.escape(item["build_date"] or "—")

        rows_html.append(
            f"""
        <tr class="img-row"
            data-name="{name_esc.lower()}"
            data-desc="{desc_esc.lower()}"
            data-ci="{html.escape(ci)}"
            data-signed="{'1' if item['signed'] else '0'}"
            data-multi="{'1' if multi else '0'}"
            data-zero="{'1' if zero_fix else '0'}">
          <td>
            <div class="img-title">
              <a href="{repo_url}" target="_blank" rel="noopener">{name_esc}</a>
              <button class="btn-verify" type="button" data-target="det-{idx}" aria-expanded="false">Verify</button>
            </div>
            <div class="desc">{desc_esc}</div>
            <div class="links">
              <a href="{hub_url}" target="_blank" rel="noopener">Docker Hub</a> ·
              <a href="{ghcr_url}" target="_blank" rel="noopener">GHCR</a> ·
              <a href="{rel_url}" target="_blank" rel="noopener">Releases{(' (' + html.escape(item['release_tag']) + ')') if item['release_tag'] else ''}</a>
            </div>
          </td>
          <td>
            <div class="mono">{ver_esc}</div>
            <div class="sub">{deb_esc}</div>
            <div class="sub">Built {bdate}</div>
          </td>
          <td>
            <div class="mono">{html.escape(arch_short)}</div>
            {size_sub}
          </td>
          <td>{ci_badge}</td>
          <td>{cve_html}</td>
          <td class="wrap-pills">{supply_html}</td>
          <td>{scorecard_html}</td>
          <td class="wrap-pills">{lic_html}</td>
        </tr>
        <tr id="det-{idx}" class="detail-row" hidden>
          <td colspan="8">
            <div class="detail-grid">
              <div>
                <div class="detail-label">Pinned pull</div>
                <pre><code>{html.escape(pull_cmd)}</code></pre>
              </div>
              <div>
                <div class="detail-label">Cosign OIDC verification</div>
                <pre><code>{html.escape(verify_cmd)}</code></pre>
              </div>
              <div>
                <div class="detail-label">SLSA Build L3 provenance verification</div>
                <pre><code>{html.escape(attest_cmd)}</code></pre>
              </div>
            </div>
          </td>
        </tr>"""
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FNX Labs Container Image Catalog — Daniel G. Cosenza</title>
  <meta name="description" content="Hardened, daily-rebuilt Debian 13 container images with Cosign OIDC signatures, SLSA Build L3 provenance, SBOMs, and zero fixable Critical/High CVEs.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://dgcosenza.github.io/">
  <meta property="og:title" content="FNX Labs Container Image Catalog — Daniel G. Cosenza">
  <meta property="og:description" content="Hardened, daily-rebuilt Debian 13 container images with Cosign OIDC signatures, SLSA Build L3 provenance, SBOMs, and zero fixable Critical/High CVEs.">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="FNX Labs Container Image Catalog — Daniel G. Cosenza">
  <meta name="twitter:description" content="Hardened, daily-rebuilt Debian 13 container images with Cosign OIDC signatures, SLSA Build L3 provenance, SBOMs, and zero fixable Critical/High CVEs.">
  <link rel="icon" href="favicon.svg" type="image/svg+xml">
  <link rel="canonical" href="https://dgcosenza.github.io/">
  <style>
    :root {{
      --bg: #0b1020;
      --surface: #121a2f;
      --surface-2: #18233f;
      --border: #253457;
      --text: #e6edf7;
      --muted: #93a4c3;
      --accent: #60a5fa;
      --ok-bg: rgba(34, 197, 94, 0.14);
      --ok-fg: #4ade80;
      --warn-bg: rgba(250, 204, 21, 0.14);
      --warn-fg: #facc15;
      --fail-bg: rgba(248, 113, 113, 0.16);
      --fail-fg: #f87171;
      --info-bg: rgba(96, 165, 250, 0.14);
      --info-fg: #93c5fd;
      --acc-bg: rgba(167, 139, 250, 0.16);
      --acc-fg: #c4b5fd;
      --muted-bg: rgba(148, 163, 184, 0.14);
    }}
    @media (prefers-color-scheme: light) {{
      :root {{
        --bg: #f6f8fc;
        --surface: #ffffff;
        --surface-2: #f1f5fb;
        --border: #d9e2ef;
        --text: #0f172a;
        --muted: #475569;
        --accent: #1d4ed8;
        --ok-bg: #dcfce7;
        --ok-fg: #166534;
        --warn-bg: #fef9c3;
        --warn-fg: #854d0e;
        --fail-bg: #fee2e2;
        --fail-fg: #991b1b;
        --info-bg: #dbeafe;
        --info-fg: #1e40af;
        --acc-bg: #ede9fe;
        --acc-fg: #5b21b6;
        --muted-bg: #e2e8f0;
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .wrap {{ max-width: 1380px; margin: 0 auto; padding: 2rem 1.25rem 3rem; }}
    header {{ margin-bottom: 1.75rem; }}
    h1 {{ margin: 0 0 0.4rem; font-size: 1.85rem; letter-spacing: -0.02em; }}
    .lead {{ margin: 0; color: var(--muted); max-width: 78ch; }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
      gap: 0.85rem;
      margin: 1.5rem 0;
    }}
    .kpi {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.95rem 1.1rem;
    }}
    .kpi-num {{ font-size: 1.6rem; font-weight: 700; letter-spacing: -0.02em; }}
    .kpi-lbl {{ font-size: 0.82rem; color: var(--muted); margin-top: 0.15rem; }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.65rem;
      align-items: center;
      margin-bottom: 1rem;
    }}
    .search {{
      flex: 1 1 260px;
      padding: 0.55rem 0.85rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text);
      font-size: 0.95rem;
    }}
    .chip {{
      padding: 0.45rem 0.8rem;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text);
      font-size: 0.84rem;
      cursor: pointer;
    }}
    .chip.active {{ background: #1d4ed8; border-color: #1d4ed8; color: #fff; }}
    .table-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow-x: auto;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th, td {{ padding: 0.8rem 0.85rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); background: var(--surface-2); white-space: nowrap; }}
    tr:last-child td {{ border-bottom: none; }}
    .img-title {{ display: flex; align-items: center; gap: 0.5rem; font-weight: 600; font-size: 0.98rem; }}
    .desc {{ color: var(--muted); font-size: 0.82rem; margin-top: 0.15rem; max-width: 40ch; }}
    .links {{ font-size: 0.78rem; color: var(--muted); margin-top: 0.25rem; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.84rem; }}
    .sub {{ display: block; font-size: 0.76rem; color: var(--muted); margin-top: 0.15rem; }}
    .pill {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      font-size: 0.74rem;
      font-weight: 600;
      white-space: nowrap;
      margin: 0.1rem 0.15rem 0.1rem 0;
    }}
    .pill.ok {{ background: var(--ok-bg); color: var(--ok-fg); }}
    .pill.warn {{ background: var(--warn-bg); color: var(--warn-fg); }}
    .pill.fail {{ background: var(--fail-bg); color: var(--fail-fg); }}
    .pill.info {{ background: var(--info-bg); color: var(--info-fg); }}
    .pill.accent {{ background: var(--acc-bg); color: var(--acc-fg); }}
    .pill.muted {{ background: var(--muted-bg); color: var(--muted); }}
    .wrap-pills {{ min-width: 145px; }}
    .btn-verify {{
      padding: 0.15rem 0.5rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: var(--text);
      font-size: 0.72rem;
      cursor: pointer;
    }}
    .detail-row td {{ background: var(--surface-2); padding: 0.9rem 1rem; }}
    .detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.85rem; }}
    .detail-label {{ font-size: 0.76rem; font-weight: 600; color: var(--muted); margin-bottom: 0.3rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    pre {{
      margin: 0;
      padding: 0.65rem 0.75rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.78rem;
    }}
    footer {{
      margin-top: 2rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 0.84rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 0.5rem;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>FNX Labs Container Image Catalog</h1>
      <p class="lead">
        Hardened, daily-rebuilt Debian 13 (<code>trixie-slim</code>) container images maintained by
        <strong>Daniel G. Cosenza from FNX Labs</strong>. Every published digest is gated on
        <strong>0 fixable Critical/High CVEs</strong> (Trivy + Grype on SBOM), efficiency-checked with Dive,
        keyless-signed with <strong>Cosign OIDC</strong>, attested with <strong>SPDX &amp; CycloneDX SBOMs</strong>
        and <strong>SLSA Build L3</strong> provenance, and mirrored with identical multi-arch digests to
        Docker Hub and GHCR.
      </p>
    </header>

    <main>
    <section class="kpis" aria-label="Catalog summary">
      <div class="kpi"><div class="kpi-num">{summary['total_images']}</div><div class="kpi-lbl">Maintained Images</div></div>
      <div class="kpi"><div class="kpi-num">{summary['passing_ci']} / {summary['total_images']}</div><div class="kpi-lbl">Passing Daily CI</div></div>
      <div class="kpi"><div class="kpi-num">{summary['zero_fixable_cves']}</div><div class="kpi-lbl">Zero Fixable Critical/High CVEs</div></div>
      <div class="kpi"><div class="kpi-num">{summary['signed_images']}</div><div class="kpi-lbl">Cosign OIDC Signed</div></div>
      <div class="kpi"><div class="kpi-num">{summary['multi_arch_images']}</div><div class="kpi-lbl">Multi-Arch (amd64 + arm64)</div></div>
    </section>

    <div class="toolbar">
      <input id="q" class="search" type="search" placeholder="Filter images by name or description..." aria-label="Filter images">
      <button class="chip active" type="button" data-filter="all">All</button>
      <button class="chip" type="button" data-filter="passing">Passing CI</button>
      <button class="chip" type="button" data-filter="signed">Signed</button>
      <button class="chip" type="button" data-filter="multi">Multi-Arch</button>
      <button class="chip" type="button" data-filter="zero">0 Fixable C/H</button>
    </div>

    <div class="table-card">
      <table>
        <thead>
          <tr>
            <th scope="col">Image</th>
            <th scope="col">Version / Base</th>
            <th scope="col">Architectures</th>
            <th scope="col">Daily CI</th>
            <th scope="col">CVE Gate</th>
            <th scope="col">Supply Chain</th>
            <th scope="col">Scorecard</th>
            <th scope="col">Licenses</th>
          </tr>
        </thead>
        <tbody id="rows">
          {''.join(rows_html)}
        </tbody>
      </table>
    </div>
    </main>

    <footer>
      <div>Maintained by <strong>Daniel G. Cosenza from FNX Labs</strong> · Packaging licensed under MIT</div>
      <div>Updated {gen_at} · <a href="catalog.json">catalog.json</a> · <a href="https://github.com/dgcosenza/dgcosenza.github.io">Source</a></div>
    </footer>
  </div>

  <script>
    (function () {{
      let activeFilter = "all";
      const q = document.getElementById("q");
      const chips = document.querySelectorAll(".chip");
      const rows = document.querySelectorAll("tr.img-row");

      function apply() {{
        const term = (q.value || "").trim().toLowerCase();
        rows.forEach((tr) => {{
          const detBtn = tr.querySelector(".btn-verify");
          const det = detBtn ? document.getElementById(detBtn.dataset.target) : null;
          let ok = true;
          if (term && !(tr.dataset.name.includes(term) || tr.dataset.desc.includes(term))) ok = false;
          if (activeFilter === "passing" && tr.dataset.ci !== "success") ok = false;
          if (activeFilter === "signed" && tr.dataset.signed !== "1") ok = false;
          if (activeFilter === "multi" && tr.dataset.multi !== "1") ok = false;
          if (activeFilter === "zero" && tr.dataset.zero !== "1") ok = false;
          tr.hidden = !ok;
          if (!ok && det) {{
            det.hidden = true;
            if (detBtn) detBtn.setAttribute("aria-expanded", "false");
          }}
        }});
      }}

      q.addEventListener("input", apply);
      chips.forEach((btn) => {{
        btn.addEventListener("click", () => {{
          chips.forEach((c) => c.classList.remove("active"));
          btn.classList.add("active");
          activeFilter = btn.dataset.filter;
          apply();
        }});
      }});

      document.querySelectorAll(".btn-verify").forEach((btn) => {{
        btn.addEventListener("click", () => {{
          const det = document.getElementById(btn.dataset.target);
          if (!det) return;
          const next = !det.hidden;
          det.hidden = next;
          btn.setAttribute("aria-expanded", String(!next));
        }});
      }});
    }})();
  </script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Build FNX Labs container catalog site.")
    parser.add_argument("--owner", default="dgcosenza")
    parser.add_argument("--out", default="site")
    args = parser.parse_args()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repos = list_docker_repos(args.owner, token)
    if not repos:
        print("ERROR: no public *-docker repositories found.", file=sys.stderr)
        return 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(fetch_repo_record, args.owner, r, token) for r in repos]
        images = [f.result() for f in futs]
    images.sort(key=lambda x: x["name"])

    summary = {
        "total_images": len(images),
        "passing_ci": sum(1 for i in images if i["ci_status"] == "success"),
        "zero_fixable_cves": sum(1 for i in images if i["fixable_critical_high"] == 0),
        "signed_images": sum(1 for i in images if i["signed"]),
        "slsa_images": sum(1 for i in images if i["slsa_provenance"]),
        "multi_arch_images": sum(1 for i in images if len(i["architectures"]) >= 2),
    }

    catalog = {
        "schema_version": 1,
        "maintainer": "Daniel G. Cosenza from FNX Labs",
        "owner": args.owner,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary,
        "images": images,
    }

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")
    (out_dir / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    page_html = "\n".join(line.rstrip() for line in render_html(catalog).splitlines()) + "\n"
    (out_dir / "index.html").write_text(page_html, encoding="utf-8")
    base_url = "https://dgcosenza.github.io/"
    (out_dir / "favicon.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Catalog icon">'
        '<rect width="64" height="64" rx="12" fill="#0b1020"/>'
        '<path d="M18 16h30v9H28v8h17v9H28v14h-10z" fill="#60a5fa"/>'
        "</svg>\n",
        encoding="utf-8",
    )
    (out_dir / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {base_url}sitemap.xml\n",
        encoding="utf-8",
    )
    (out_dir / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>{base_url}</loc></url>\n"
        "</urlset>\n",
        encoding="utf-8",
    )

    print(
        f"Built catalog in {out_dir}: {summary['total_images']} images, "
        f"{summary['passing_ci']} passing CI, {summary['zero_fixable_cves']} zero fixable C/H, "
        f"{summary['signed_images']} signed, {summary['multi_arch_images']} multi-arch."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
