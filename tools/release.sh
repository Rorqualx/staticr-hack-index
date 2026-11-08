#!/usr/bin/env bash
# Publish a signed index: build -> sign (main key, macOS Keychain) -> verify -> GitHub release.
# The launcher reads https://github.com/Rorqualx/staticr-hack-index/releases/latest/download/index.json
# and index.json.sig, and checks the signature against the keys it pins (keys/*.pub here).
#
#   tools/release.sh [--dry-run] [--allow-empty] [--key-id ID | --key-file FILE]
#
# Re-run before the current index expires (180 days after its date) or the launcher stops
# trusting it. Needs: gh (logged in), a python with `cryptography` (.venv/bin/python here).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-.venv/bin/python}"
dry=0; empty=(); key=(--keychain 24b60ded8adbf7b2)
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry=1 ;;
    --allow-empty) empty=(--allow-empty) ;;
    --key-id) key=(--keychain "$2"); shift ;;
    --key-file) key=(--key-file "$2"); shift ;;
    *) echo "usage: $0 [--dry-run] [--allow-empty] [--key-id ID | --key-file FILE]" >&2; exit 2 ;;
  esac
  shift
done
[ -z "$(git status --porcelain -- entries revoked.json registry keys)" ] \
  || { echo "release: entries/revoked/registry/keys have uncommitted changes" >&2; exit 1; }
today="$(date -u +%Y-%m-%d)"
"$PY" tools/hackindex.py validate "${empty[@]}"
"$PY" tools/hackindex.py build --generated "$today" "${empty[@]}" --out dist/index.json
"$PY" tools/hackindex.py sign dist/index.json "${key[@]}"
"$PY" tools/hackindex.py verify dist/index.json
sha="$(git rev-parse --short HEAD)"
tag="index-$today-$sha"
if [ "$dry" = 1 ]; then echo "dry run: would publish $tag"; exit 0; fi
git push -q origin HEAD
gh release create "$tag" dist/index.json dist/index.json.sig --latest \
  --title "Index $today ($sha)" --notes "Signed staticR hack index built from $sha on $today."
echo "published $tag"
