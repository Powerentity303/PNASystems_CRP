"""pnasyscrp CLI: setup | enable | disable | revokeapi | selftest."""
from __future__ import annotations

import getpass
import json
import os
import sys
import urllib.request
import uuid
from pathlib import Path

from .crypto_local import (
    decrypt_local,
    derive_key_iv,
    encrypt_local,
    make_access_sha1024,
    make_access_variant,
    make_pi_blob,
    sha256_hex,
)

HOME = Path.home()
SAFE_DIR = HOME / ".pnasys_crp"
VAULT = SAFE_DIR / ".vault"
STATE = SAFE_DIR / "state.json"
CREDS_TXT = VAULT / "creds.txt"  # username + password, perms 600
PI_BLOB_FILE = VAULT / "pi_blob.ref"
ACCESS_FILE = VAULT / "access.enc.json"  # AES-GCM encrypted access key (never printed)


def _ensure_dirs() -> None:
    SAFE_DIR.mkdir(mode=0o700, exist_ok=True)
    VAULT.mkdir(mode=0o700, exist_ok=True)
    try:
        os.chmod(SAFE_DIR, 0o700)
        os.chmod(VAULT, 0o700)
    except Exception:
        pass


def _load_state() -> dict:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except Exception:
            return {}
    return {}


def _save_state(s: dict) -> None:
    _ensure_dirs()
    STATE.write_text(json.dumps(s, indent=2))
    try:
        os.chmod(STATE, 0o600)
    except Exception:
        pass


def _require_setup() -> dict:
    s = _load_state()
    if not s.get("setup_done"):
        print("Setup not complete. Run: pnasyscrp setup", file=sys.stderr)
        sys.exit(2)
    return s


def cmd_setup(vercel_base: str) -> int:
    _ensure_dirs()
    print("PNASystems_CRP setup")
    fav_rest = input("Favorite restaurant: ").strip()
    fav_animal = input("Favorite animal: ").strip()
    fav_color = input("Favorite color: ").strip()
    pi_user = input("Raspberry Pi username: ").strip()
    pi_pass = getpass.getpass("Raspberry Pi password: ")
    enc_password = getpass.getpass("Local encryption password (anything): ")
    if not all([fav_rest, fav_animal, fav_color, pi_user, pi_pass, enc_password]):
        print("All fields required.", file=sys.stderr)
        return 2

    # Key/IV derivation check (password -> key + iv/salt).
    _key, _iv_seed = derive_key_iv(enc_password)

    # 1) Save username/password txt FIRST (plaintext, 600 perms).
    CREDS_TXT.write_text(f"{pi_user}\n{pi_pass}\n")
    try:
        os.chmod(CREDS_TXT, 0o600)
    except Exception:
        pass

    # 2) Pi blob: uuid v4 + interleave(h(uuid), h(color), h(rest)).
    uuid1 = str(uuid.uuid4())
    pi_blob = make_pi_blob(uuid1, fav_color, fav_rest)
    PI_BLOB_FILE.write_text(pi_blob)
    try:
        os.chmod(PI_BLOB_FILE, 0o600)
    except Exception:
        pass

    # 3) Access key variant: new uuid2, re-hash each + interleave, then SHA1024.
    _, uuid2, access_key = make_access_variant(uuid1, fav_color, fav_rest)
    _ = fav_animal  # collected per spec; reserved for future key math
    _ = make_access_sha1024(pi_blob, uuid1, fav_color, fav_rest)  # local pi identity ref

    # 4) Encrypt access key locally so enable/disable work without re-prompt;
    #    never print it.
    enc_bundle = encrypt_local(access_key.encode(), enc_password)
    ACCESS_FILE.write_text(json.dumps(enc_bundle))
    try:
        os.chmod(ACCESS_FILE, 0o600)
    except Exception:
        pass

    # 5) Send BOTH keys to Vercel register API (server encrypts pi blob with
    #    derived pnasys key and stores under sha256(access_key) filename).
    #    Pi blob itself is never recoverable via the package afterwards.
    payload = json.dumps({"pi_blob": pi_blob, "access_key": access_key}).encode()
    req = urllib.request.Request(
        vercel_base.rstrip("/") + "/api/register",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode()[:300]
    except Exception as e:
        print(f"Register failed: {e}", file=sys.stderr)
        return 1
    _save_state({"setup_done": True, "vercel_base": vercel_base,
                 "uuid2_ref": sha256_hex(uuid2)[:16]})
    print("Setup complete. Register response: " + body)
    print(f"Vault: {VAULT} (creds.txt 600, pi_blob saved, access key encrypted locally)")
    return 0


def _load_access_key() -> tuple[str, str]:
    """Return (access_key, password). Neither is ever printed by callers."""
    enc_password = getpass.getpass("Local encryption password: ")
    bundle = json.loads(ACCESS_FILE.read_text())
    return decrypt_local(bundle, enc_password).decode(), enc_password


def cmd_enable() -> int:
    try:
        from .daemon import start_daemon
    except ImportError:  # installed-layout fallback
        from pnasystems_crp.daemon import start_daemon  # type: ignore[no-redef]

    _require_setup()
    _access_key, pw = _load_access_key()  # never printed
    del _access_key  # daemon_run reloads from vault; keep secret out of argv/ps
    return start_daemon(pw)


def cmd_disable() -> int:
    try:
        from .daemon import stop_daemon
    except ImportError:  # installed-layout fallback
        from pnasystems_crp.daemon import stop_daemon  # type: ignore[no-redef]

    _require_setup()
    return stop_daemon()


def cmd_revokeapi(vercel_base: str) -> int:
    _require_setup()
    ans = input("Type YES to revoke API keys (requires setup again): ").strip()
    if ans != "YES":
        print("Aborted.")
        return 2
    access_key, _pw = _load_access_key()
    payload = json.dumps({"access_key": access_key}).encode()
    del access_key
    req = urllib.request.Request(
        vercel_base.rstrip("/") + "/api/revoke",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(r.read().decode()[:300])
    except Exception as e:
        print(f"Revoke failed: {e}", file=sys.stderr)
        return 1
    # Force setup again.
    _save_state({"setup_done": False, "vercel_base": vercel_base})
    for f in (ACCESS_FILE, PI_BLOB_FILE, CREDS_TXT):
        try:
            if f.exists():
                f.unlink()
        except Exception:
            pass
    print("Revoked locally. Run `pnasyscrp setup` again.")
    return 0


def cmd_selftest() -> int:
    """Offline crypto round-trip check. No network, no secrets printed."""
    from .crypto_local import derive_pi_encryption_key

    pw = "selftest-pw"
    key, iv = derive_key_iv(pw)
    assert len(key) == 32 and len(iv) == 12
    bundle = encrypt_local(b"hello-pi", pw)
    assert decrypt_local(bundle, pw) == b"hello-pi"
    u1 = "12345678-1234-5678-1234-567812345678"
    blob = make_pi_blob(u1, "blue", "tacos")
    assert len(blob) == 64 * 3
    _, _u2, access = make_access_variant(u1, "blue", "tacos", uuid2="87654321-4321-8765-4321-876543218765")
    assert len(access.split("-")) == 4
    ek = derive_pi_encryption_key(access)
    assert len(ek.split("-")) == 4
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print("selftest OK: AES-GCM round-trip, pi blob, SHA1024, pi-key derivation")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    vercel_base = os.environ.get("PNASYS_VERCEL_BASE", "https://pnasys-crp-api.vercel.app")
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("Usage: pnasyscrp {setup|enable|disable|revokeapi|selftest}")
        return 0
    cmd = argv[0].lower()
    if cmd == "setup":
        return cmd_setup(vercel_base)
    if cmd == "enable":
        return cmd_enable()
    if cmd == "disable":
        return cmd_disable()
    if cmd == "revokeapi":
        return cmd_revokeapi(vercel_base)
    if cmd == "selftest":
        return cmd_selftest()
    print(f"Unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
