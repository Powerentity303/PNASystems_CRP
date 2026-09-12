"""pnasyscrp — Pi side (no TPM: AES vault + pnasys transport).

  pnasyscrp setup | enable | disable | revokeapi | selftest | update
  pnasyscrp ssh setup    link this Pi to a computer (pairing code flow)
  pnasyscrp ssh enable   presence + secure queue listener (runs root-aware)
"""
from __future__ import annotations

import getpass
import json
import os
import sys
import time
import uuid
from pathlib import Path

from pnasyscnct import link as L
from pnasyscnct.common import (decrypt_local, derive_key_iv, encrypt_local,
                               generate_session_key, make_access_sha1024,
                               make_access_variant, make_pi_blob, secure_pack,
                               secure_unpack, sha256_hex)

HOME = Path.home()
SAFE = HOME / ".pnasys_crp"
VAULT = SAFE / ".vault"
CREDS = VAULT / "creds.txt"
PI_BLOB = VAULT / "pi_blob.ref"
ACCESS = VAULT / "access.enc.json"
SESSION = VAULT / "session.key"
LAST_EVENT = SAFE / "last_event"
IDLE_SECONDS = 600


def _ensure() -> None:
    SAFE.mkdir(mode=0o700, parents=True, exist_ok=True)
    VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)


def _chmod(p: Path) -> None:
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def _confirm_overwrite() -> bool:
    if L.load_state().get("setup_done"):
        ans = input("Already set up. Overwrite? [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            print("Keeping existing setup.")
            return False
    return True


def _offer_cleanup(created: set[str]) -> None:
    others: list[str] = []
    for base in (SAFE, VAULT):
        if not base.exists():
            continue
        for p in base.iterdir():
            if p.is_file() and str(p) not in created:
                others.append(p.name)
    if not others:
        return
    print(f"Old files present: {', '.join(sorted(others))}")
    if input("Delete old files? [y/N]: ").strip().lower() in ("y", "yes"):
        for base in (SAFE, VAULT):
            for p in base.iterdir():
                if p.is_file() and str(p) not in created:
                    try:
                        p.unlink()
                    except Exception:
                        pass
        print("Old files deleted.")


def cmd_setup() -> int:
    from pnasyscnct.link import base

    if not _confirm_overwrite():
        return 0
    _ensure()
    print("pnasyscrp setup (Pi)")
    fav_rest = input("Favorite restaurant: ").strip()
    fav_animal = input("Favorite animal: ").strip()
    fav_color = input("Favorite color: ").strip()
    pi_user = input("Raspberry Pi username: ").strip()
    pi_pass = getpass.getpass("Raspberry Pi password: ")
    local_pw = getpass.getpass("Local encryption password (anything): ")
    if not all([fav_rest, fav_animal, fav_color, pi_user, pi_pass, local_pw]):
        print("All fields required.", file=sys.stderr)
        return 2
    _ = derive_key_iv(local_pw)
    CREDS.write_text(json.dumps(encrypt_local(f"{pi_user}\n{pi_pass}\n".encode(), local_pw)))
    uuid1 = str(uuid.uuid4())
    blob = make_pi_blob(uuid1, fav_color, fav_rest)
    PI_BLOB.write_text(blob)
    _, uuid2, access = make_access_variant(uuid1, fav_color, fav_rest)
    _ = fav_animal, make_access_sha1024(blob, uuid1, fav_color, fav_rest)
    ACCESS.write_text(json.dumps(encrypt_local(access.encode(), local_pw)))
    for f in (CREDS, PI_BLOB, ACCESS):
        _chmod(f)
    import urllib.request

    payload = json.dumps({"pi_blob": blob, "access_key": access}).encode()
    req = urllib.request.Request(base().rstrip("/") + "/api/register", data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print("Register response: " + r.read().decode()[:200])
    except Exception as e:
        print(f"Register failed: {e}", file=sys.stderr)
        return 1
    L.save_state({"setup_done": True, "uuid2_ref": sha256_hex(uuid2)[:16]})
    print("Setup complete. Vault sealed (AES).")
    print("Your device is registered. Use the device name you choose at")
    print("`pnasyscrp ssh setup` from the computer side — no keys displayed here.")
    _offer_cleanup({str(CREDS), str(PI_BLOB), str(ACCESS), str(L.STATE)})
    return 0


def _load_access() -> tuple[str, str]:
    pw = getpass.getpass("Local encryption password: ")
    return decrypt_local(json.loads(ACCESS.read_text()), pw).decode(), pw


def cmd_enable() -> int:
    from pnasyscnct.pi_daemon import start_daemon

    if not L.load_state().get("setup_done"):
        print("Run: pnasyscrp setup", file=sys.stderr)
        return 2
    _access, _pw = _load_access()
    del _access
    session = generate_session_key()
    SESSION.write_text(session + "\n")
    _chmod(SESSION)
    print("Session key: " + session)
    return start_daemon(_pw)


def cmd_disable() -> int:
    from pnasyscnct.pi_daemon import stop_daemon

    return stop_daemon()


def cmd_revokeapi() -> int:
    import urllib.request

    if input("Type YES to revoke (setup again after): ").strip() != "YES":
        print("Aborted.")
        return 2
    access, _pw = _load_access()
    payload = json.dumps({"access_key": access}).encode()
    del access
    req = urllib.request.Request(L.base().rstrip("/") + "/api/revoke", data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(r.read().decode()[:200])
    except Exception as e:
        print(f"Revoke failed: {e}", file=sys.stderr)
        return 1
    L.save_state({"setup_done": False})
    for f in (ACCESS, PI_BLOB, CREDS, SESSION):
        try:
            f.unlink(missing_ok=True)
        except Exception:
            pass
    print("Revoked. Run `pnasyscrp setup` again.")
    return 0


def cmd_selftest() -> int:
    from pnasyscnct.common import secure_pack as _sp
    from pnasyscnct.common import secure_unpack as _su

    pw = "selftest-pw"
    assert decrypt_local(encrypt_local(b"x", pw), pw) == b"x"
    sk = generate_session_key()
    assert len(sk.split("=")) == 6
    assert _su("k", _sp("k", {"a": 1})) == {"a": 1}
    print("selftest OK")
    return 0


def cmd_update() -> int:
    import subprocess
    import tempfile
    import urllib.request

    # Pi updates touch system packages: prove root first via sudo's own prompt.
    print("Root check (enter your sudo password):")
    if subprocess.run(["sudo", "-v"]).returncode != 0:
        print("sudo authentication failed.", file=sys.stderr)
        return 1
    owner = os.environ.get("PNA_OWNER", "Powerentity303")
    ref = os.environ.get("PNA_REF", "main")
    url = (f"https://raw.githubusercontent.com/{owner}/PNASystems_CRP/"
           f"{ref}/installer.sh?nocache={int(time.time())}")
    print(f"Updating from {owner}/PNASystems_CRP@{ref} ...")
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            script = r.read()
    except Exception as e:
        print(f"Download failed: {e}", file=sys.stderr)
        return 1
    with tempfile.NamedTemporaryFile("wb", suffix=".sh", delete=False) as f:
        f.write(script)
        path = f.name
    try:
        return subprocess.run(["bash", path]).returncode
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def cmd_ssh_setup() -> int:
    """Pairing: ask pairing key first, emit encrypted code, link via Vercel."""
    if not L.load_state().get("setup_done"):
        print("Run: pnasyscrp setup", file=sys.stderr)
        return 2
    access, local_pw = _load_access()
    pi_ident = sha256_hex(access)
    pair_key = getpass.getpass("Pairing encryption key (tell the computer this): ")
    if not pair_key:
        print("Pairing key required.", file=sys.stderr)
        return 2
    code = generate_session_key()
    # CHECK-1: show the SAS now; the computer shows the same after decrypt.
    # Both humans compare before the computer answers.
    print(f"CHECK-1 SAS (computer must show the same): {L.sas(pair_key, code)}")
    blob = secure_pack(pair_key, {"pi_ident": pi_ident, "code": code,
                                  "ts": int(time.time())})
    computer_id = input("Computer ID (from `pnasyscnct setup`): ").strip()
    if not computer_id:
        print("Computer ID required.", file=sys.stderr)
        return 2
    dev_name = input("Device name for this Pi (computer connects with it): ").strip()
    if not dev_name:
        print("Device name required.", file=sys.stderr)
        return 2
    r = L.link_request(computer_id, blob)
    if not r.get("ok"):
        print(f"Pairing request failed: {r}", file=sys.stderr)
        return 1
    print("Link code sent. On the computer: `pnasyscnct setup --ssh`.")
    print("Waiting for the computer's answer (it will ask you for the key when it arrives)...")
    ans = None
    while ans is None:
        try:
            r = L.link_wait(computer_id, pi_ident)
        except KeyboardInterrupt:
            print("\nStopped.")
            return 130
        except Exception as e:
            print(f"wait error, retrying: {e}")
            time.sleep(3)
            continue
        if r.get("empty"):
            continue
        ans = r
    check = getpass.getpass("Computer answered. Enter pairing key to decrypt + verify: ")
    try:
        inner = secure_unpack(check, ans["blob"])
        assert inner.get("computer_id") == computer_id and inner.get("ok")
        # CHECK-2: answer must echo our code — proves computer decrypted us.
        assert inner.get("code_echo") == L.code_echo(code), "code echo mismatch"
        link_key = inner["link_key"]
    except Exception:
        print("Verify failed — wrong key or code echo mismatch (MITM?).", file=sys.stderr)
        return 1
    L.pi_save_link(computer_id, pi_ident, link_key, local_pw, name=dev_name)
    # Fresh pairing owns the fingerprint pin: reset it under access-key auth.
    try:
        L.reset_pin(pi_ident, what="all", access_key=access)
    except Exception as e:
        print(f"pin reset note: {e}")
    del access
    print(f"Linked as '{dev_name}' and verified. Run: pnasyscrp ssh enable")
    return 0


def cmd_delete() -> int:
    """Wipe this Pi: local files + GitHub queue/presence purged + tombstoned.

    After this, computers trying to connect fail with the reason and are
    offered local removal. Requires re-setup + re-pair to use again.
    """
    if not L.load_state().get("setup_done"):
        print("Nothing set up.", file=sys.stderr)
        return 2
    access, _pw = _load_access()
    pi_ident = sha256_hex(access)
    if input("Delete THIS PI (local files + GitHub data + tombstone)? "
             "Type YES: ").strip() != "YES":
        print("Aborted.")
        return 2
    try:
        r = L.purge(pi_ident, access_key=access)
        print(f"GitHub purge: {'ok' if r.get('ok') else r}")
    except Exception as e:
        print(f"Purge failed: {e}", file=sys.stderr)
    try:
        L.reset_pin(pi_ident, what="pin", access_key=access)
    except Exception:
        pass
    try:
        r = L.mark_deleted(pi_ident, access_key=access)
        print(f"Tombstone: {'written' if r.get('ok') else r}")
    except Exception as e:
        print(f"Tombstone failed: {e}", file=sys.stderr)
    del access
    for f in (ACCESS, PI_BLOB, CREDS, SESSION, VAULT / "link.enc.json",
              VAULT / "listener.env"):
        try:
            f.unlink(missing_ok=True)
        except Exception:
            pass
    L.save_state({"setup_done": False, "devices": {}})
    print("Pi deleted. Re-run setup + pairing to use again.")
    return 0


def cmd_ssh_enable() -> int:
    from pnasyscnct.pi_daemon import run_ssh_presence

    if not L.load_state().get("setup_done"):
        print("Run: pnasyscrp setup", file=sys.stderr)
        return 2
    _access, pw = _load_access()
    del _access
    try:
        L.pi_load_link(pw)
    except Exception:
        print("Not linked yet. Run: pnasyscrp ssh setup", file=sys.stderr)
        return 2
    print("SSH presence live. Waiting for `pnasyscnct ssh` (Ctrl+C to stop).")
    return run_ssh_presence(pw)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("Usage: pnasyscrp {setup|enable|disable|revokeapi|selftest|update|delete|ssh setup|ssh enable}")
        return 0
    if argv[0] == "ssh" and len(argv) > 1 and argv[1] == "setup":
        return cmd_ssh_setup()
    if argv[0] == "ssh" and len(argv) > 1 and argv[1] == "enable":
        return cmd_ssh_enable()
    return {"setup": cmd_setup, "enable": cmd_enable, "disable": cmd_disable,
            "revokeapi": cmd_revokeapi, "selftest": cmd_selftest,
            "update": cmd_update, "delete": cmd_delete}.get(argv[0], lambda: (print(f"Unknown: {argv[0]}",
                                                              file=sys.stderr), 2)[1])()


if __name__ == "__main__":
    raise SystemExit(main())
