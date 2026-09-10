#!/usr/bin/env bash
# Installer pulled from GitHub per README. Pi 4/5, headless + desktop.
set -euo pipefail
OWNER="${OWNER:-Powerentity303}"
REF="${REF:-main}"
REPO="PNASystems_CRP"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "[pnasyscrp] fetching $OWNER/$REPO@$REF ..."
git clone --depth 1 --branch "$REF" "https://github.com/$OWNER/$REPO.git" "$TMP/repo" 2>/dev/null \
  || git clone --depth 1 "https://github.com/$OWNER/$REPO.git" "$TMP/repo"
python3 -m pip install --user "$TMP/repo/public_package"
echo "[pnasyscrp] installed. Ensure ~/.local/bin is on PATH. Run: pnasyscrp setup"
