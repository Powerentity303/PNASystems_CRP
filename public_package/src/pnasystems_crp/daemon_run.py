"""Entry point for background service: reloads encrypted access key, runs loop."""
import getpass
import json
from pathlib import Path

from .crypto_local import decrypt_local
from .daemon import run_forever

VAULT = Path.home() / ".pnasys_crp" / ".vault"


def main() -> None:
    # systemd has no TTY; password must come from env set at enable time?
    # Simplest headless-safe approach: enable step caches a session key?
    # v0: prompt if TTY, else read PNASYS_PW env (set by `enable` wrapper).
    import os

    pw = os.environ.get("PNASYS_PW") or (getpass.getpass("Local encryption password: ") if os.isatty(0) else "")
    if not pw:
        raise SystemExit("PNASYS_PW not set for background service")
    bundle = json.loads((VAULT / "access.enc.json").read_text())
    access_key = decrypt_local(bundle, pw).decode()
    run_forever(access_key)


if __name__ == "__main__":
    main()
