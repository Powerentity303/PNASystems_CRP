# pnasyscnct — tailscale-style Pi remote (computer + Pi)

One package, both ends. Install on Windows 11 (TPM 2.0) and on Pi 4/5
(Raspberry Pi OS, headless or desktop) — via pip or via GitHub, identical:

```bash
pip install pnasyscnct
# or:
pip install git+https://github.com/Powerentity303/PNASystems_CRP.git
# or the one-liner (venv-safe on Pi OS):
curl -fsSL https://raw.githubusercontent.com/Powerentity303/PNASystems_CRP/main/installer.sh | bash
```

This gives you **both** commands: `pnasyscnct` (computer) and `pnasyscrp` (Pi).

## Computer

The computer side runs on Windows 11 (TPM 2.0) **and Linux** (any distro
with Python 3.10+; installer uses `apt` on Debian/Ubuntu, otherwise
pre-install `git python3-venv`). Off-Windows the vault falls back to
AES-GCM (same API); only the key sealing differs.

```bash
pnasyscnct setup            # same questions + TPM-sealed vault, prints computer ID
pnasyscnct setup --ssh      # scan for the Pi's pairing request, verify, rotate link key
pnasyscnct ssh MyPi         # asks link encryption key, remote shell (reconnects)
pnasyscnct mcp --enckey K --sshdev MyPi   # MCP server (OpenCode), SSH always active
pnasyscnct update           # reinstall latest (cache-busted)
```

OpenCode (`opencode.json`):

```json
{"mcp": {"pnasys-ssh": {"type": "local",
  "command": ["pnasyscnct", "mcp", "--enckey", "LINK_KEY", "--sshdev", "MyPi"],
  "enabled": true}}}
```

## Pi

```bash
pnasyscrp setup             # identity + AES vault (overwrite confirm, old-file cleanup)
pnasyscrp enable            # listener + fresh session key (10-min idle auto-off)
pnasyscrp ssh setup         # pairing: key first, code issued, computer ID + device name
pnasyscrp ssh enable        # presence + listener (root-aware exec)
pnasyscrp update            # sudo-gated reinstall latest (cache-busted)
pnasyscrp delete            # wipe Pi + purge GitHub + tombstone (blocks reconnects)
```

Linking in short: computer `setup --ssh` scans → Pi `ssh setup` sends an
encrypted pairing code to that computer ID → computer verifies with the
pairing key, both adopt a fresh link key → Pi verifies the answer the same
way. Vercel only relays opaque blobs. Pi exec runs root-aware (`sudo -n`
when not uid 0). Installer and Pi `update` gate on `sudo -v` (root password).

Mutual verification (MITM-resistant):
- CHECK-1 SAS: pairing key + code hash shown on both screens, humans compare.
- CHECK-2 code echo: the answer proves decryption by echoing the code hash.
- CHECK-3 session handshake: joins carry nonce + key fingerprint (pinned
  server-side, mismatch = 403); the Pi posts an ack proving key possession.
A Pi `delete` writes a tombstone: connects fail with the reason and offer
local removal until re-pairing clears it.
