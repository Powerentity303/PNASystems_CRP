#!/usr/bin/env bash
# Installer pulled from GitHub per README. Pi 4/5, headless (Lite) + desktop.
# Raspberry Pi OS is PEP 668 externally-managed, so we install into a venv
# at ~/.pnasys_crp/.venv and link pnasyscrp into ~/.local/bin (no sudo pip,
# no --break-system-packages).
set -euo pipefail
OWNER="${OWNER:-Powerentity303}"
REF="${REF:-main}"
REPO="PNASystems_CRP"
VENV="$HOME/.pnasys_crp/.venv"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "[pnasyscrp] fetching $OWNER/$REPO@$REF ..."
if ! command -v git >/dev/null 2>&1; then
  echo "[pnasyscrp] installing git (needs sudo)..."
  sudo apt-get update && sudo apt-get install -y git
fi
if [ ! -x "$VENV/bin/python" ]; then
  if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "[pnasyscrp] installing python3-venv (needs sudo)..."
    sudo apt-get update && sudo apt-get install -y python3-venv python3-full
  fi
  python3 -m venv "$VENV"
fi
git clone --depth 1 --branch "$REF" "https://github.com/$OWNER/$REPO.git" "$TMP/repo" 2>/dev/null \
  || git clone --depth 1 "https://github.com/$OWNER/$REPO.git" "$TMP/repo"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install "$TMP/repo/public_package"
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV/bin/pnasyscrp" "$HOME/.local/bin/pnasyscrp"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
     export PATH="$HOME/.local/bin:$PATH" ;;
esac
echo "[pnasyscrp] installed. Run: pnasyscrp setup"
