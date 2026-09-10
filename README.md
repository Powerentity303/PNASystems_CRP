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
export PNASYS_VERCEL_BASE="https://<your-vercel-app>.vercel.app"
pnasyscrp setup      # fav restaurant/animal/color, pi user/pass, local pw
pnasyscrp enable     # background listening server (systemd user unit, nohup fallback)
pnasyscrp disable    # stop listener
pnasyscrp revokeapi  # confirm YES -> deletes keys via Vercel API, setup again
```

`enable`/`disable` require `setup` first. `revokeapi` requires confirmation
and forces re-setup. The Pi identity blob is not recoverable via the package.
