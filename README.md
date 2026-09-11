# PNASystems_CRP (`pnasyscrp`) — Pi 4/5, headless + desktop

Public package. Command is `pnasyscrp`, install name `PNASystems_CRP`.

## Install via GitHub (no package-registry verification needed)

```bash
curl -fsSL https://raw.githubusercontent.com/Powerentity303/PNASystems_CRP/main/installer.sh | bash
# or pinned:
# curl -fsSL https://raw.githubusercontent.com/Powerentity303/PNASystems_CRP/v0.1.0/installer.sh | bash
```

The installer clones this repo, installs `PNASystems_CRP` with pip, and puts
`pnasyscrp` on PATH. Works on Raspberry Pi OS (64-bit) on Pi 4 and Pi 5,
headless (Lite) and desktop.

## Usage

```bash
pnasyscrp setup      # restaurant/animal/color, pi user/pass, local pw, channel key
pnasyscrp enable     # listener on + prints session key (keygen, H1=H2=H3=rH3=rH2=rH1)
pnasyscrp disable    # stop listener
pnasyscrp revokeapi  # confirm YES -> deletes keys via Vercel API, setup again
pnasyscrp selftest   # offline crypto check (no network)
```

No export needed: the API base defaults to `https://pnasys-crp-api.vercel.app`
and is saved at setup. Only set `PNASYS_VERCEL_BASE` if you point at a
different deployment (e.g. a preview URL for testing).

`enable` asks for the password you set at setup (unlocks the vault), then
prints a fresh session key. The listener **auto-disables after 10 minutes
with no new event**. `enable`/`disable` require `setup` first. `revokeapi`
requires confirmation and forces re-setup. The Pi identity blob is not
recoverable via the package.

AI access: install `pnasys-crp-mcp` (`pip install pnasys-crp-mcp` or
`uvx pnasys-crp-mcp`) and add it to OpenCode — the AI passes your api key +
channel key per call; ops travel encrypted, the Pi decrypts them.

`enable`/`disable` require `setup` first. `revokeapi` requires confirmation
and forces re-setup. The Pi identity blob is not recoverable via the package.
