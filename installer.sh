#!/usr/bin/env bash
# pnasyscnct installer: Pi 4/5 (headless/Lite + desktop) and Linux PCs.
# PEP 668-safe: installs into ~/.pnasys_crp/.venv, links both CLIs.
set -euo pipefail
OWNER="${OWNER:-Powerentity303}"
REF="${REF:-main}"
REPO="PNASystems_CRP"
MODE="${MODE:-github}"
VENV="$HOME/.pnasys_crp/.venv"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "[pnasyscnct] root check — enter your sudo password:"
sudo -v || { echo "[pnasyscnct] sudo authentication failed." >&2; exit 1; }
if ! command -v git >/dev/null 2>&1; then
  sudo apt-get update && sudo apt-get install -y git
fi
if [ ! -x "$VENV/bin/python" ]; then
  if ! python3 -m venv --help >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y python3-venv python3-full
  fi
  python3 -m venv "$VENV"
fi
if [ "$MODE" = "pypi" ]; then
  "$VENV/bin/pip" install --quiet --upgrade pip pnasyscnct
else
  echo "[pnasyscnct] fetching $OWNER/$REPO@$REF ..."
  git clone --depth 1 --branch "$REF" "https://github.com/$OWNER/$REPO.git" "$TMP/repo" 2>/dev/null \
    || git clone --depth 1 "https://github.com/$OWNER/$REPO.git" "$TMP/repo"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install "$TMP/repo"
fi
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV/bin/pnasyscnct" "$HOME/.local/bin/pnasyscnct"
ln -sf "$VENV/bin/pnasyscrp" "$HOME/.local/bin/pnasyscrp"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
     export PATH="$HOME/.local/bin:$PATH" ;;
esac
echo "[pnasyscnct] installed. Computer: pnasyscnct setup | Pi: pnasyscrp setup"
