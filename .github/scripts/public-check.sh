#!/usr/bin/env bash
# Public-content check: fails if deployment-specific or personal details appear
# in tracked files or generated site output, and verifies LICENSE + attribution.
set -euo pipefail
ATTRIBUTION='Daniel G. Cosenza from FNX Labs'
FORBIDDEN='192\.168\.[0-9]+\.[0-9]+|(^|[^0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|fnxlabs-|\.net\.ar|fnxusa|benjacszotk|tailscale|tailnet|\.ts\.net|homelab|home server|\bfleet\b|/opt/fnx|/home/fnx|Downloads/AI|fnxrollback|docker-tag-(check|promote)|update-all|\bpc0[0-9]\b|\b(codex|claude|antigravity|opencode|grok|gemini)\b|@gmail\.com|@duck\.com|\bART\b'
fail=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git grep -nIiE "$FORBIDDEN" -- . ':!.github/scripts/public-check.sh' ':!.gitignore'; then
    echo "::error::Forbidden deployment-specific or personal content found in tracked files."
    fail=1
  fi
fi
if [ -d site ]; then
  if grep -rnIiE "$FORBIDDEN" site/; then
    echo "::error::Forbidden deployment-specific or personal content found in generated site/."
    fail=1
  fi
fi
[ -f LICENSE ] || { echo "::error::LICENSE file is missing at repository root."; fail=1; }
grep -qF "$ATTRIBUTION" LICENSE || { echo "::error::LICENSE must name the copyright holder as \"$ATTRIBUTION\"."; fail=1; }
grep -qF "$ATTRIBUTION" README.md || { echo "::error::README.md must name the maintainer as \"$ATTRIBUTION\"."; fail=1; }
if [ -n "${PR_TEXT:-}" ] && printf '%s' "$PR_TEXT" | grep -nIiE "$FORBIDDEN"; then
  echo "::error::Pull request title/body contains forbidden content."
  fail=1
fi
exit "$fail"
