"""pnasyscnct — computer side (Windows 11, TPM 2.0).

  pnasyscnct setup            fav restaurant/animal/color + pc user/pass + local pw
  pnasyscnct setup --ssh      link a Pi (scan for its pairing request)
  pnasyscnct ssh              remote shell into the linked Pi (reconnects)
  pnasyscnct mcp --enckey K   stdio MCP server, SSH always active
  pnasyscnct selftest         offline crypto check
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import sys
import time
import uuid
from pathlib import Path

from pnasyscnct import link as L
from pnasyscnct.common import (decrypt_local, derive_key_iv, encrypt_local,
                               generate_session_key, interleave3, make_access_sha1024,
                               make_access_variant, make_pi_blob, secure_pack,
                               secure_unpack, sha256_hex)

HOME = Path.home()
SAFE = HOME / ".pnasys_crp"
VAULT = SAFE / ".vault"
CREDS = VAULT / "creds.txt"
ACCESS = VAULT / "access.enc.json"


def _ensure() -> None:
    SAFE.mkdir(mode=0o700, parents=True, exist_ok=True)
    VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)


def _save_state(s: dict) -> None:
    _ensure()
    cur = L.load_state()
    cur.update(s)
    (SAFE / "state.json").write_text(json.dumps(cur, indent=2))


def _offer_cleanup(created: set[str]) -> None:
    others = sorted(p.name for base in (SAFE, VAULT) if base.exists() for p in base.iterdir()
                    if p.is_file() and str(p) not in created)
    if not others:
        return
    print(f"Old files present: {', '.join(others)}")
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
    _ensure()
    if L.load_state().get("setup_done"):
        if input("Already set up. Overwrite? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("Keeping existing setup.")
            return 0
    print("pnasyscnct setup (computer)")
    fav_rest = input("Favorite restaurant: ").strip()
    fav_animal = input("Favorite animal: ").strip()
    fav_color = input("Favorite color: ").strip()
    pc_user = input("Computer username: ").strip()
    pc_pass = _getpass("Computer password: ")
    local_pw = _getpass("Local encryption password (anything): ")
    if not all([fav_rest, fav_animal, fav_color, pc_user, pc_pass, local_pw]):
        print("All fields required.", file=sys.stderr)
        return 2
    _ = derive_key_iv(local_pw)
    CREDS.write_text(json.dumps(encrypt_local(f"{pc_user}\n{pc_pass}\n".encode(), local_pw)))
    computer_id = uuid.uuid4().hex
    uuid1 = str(uuid.uuid4())
    blob = make_pi_blob(uuid1, fav_color, fav_rest)
    _, _u2, access = make_access_variant(uuid1, fav_color, fav_rest)
    _ = fav_animal, make_access_sha1024(blob, uuid1, fav_color, fav_rest)
    ACCESS.write_text(json.dumps(encrypt_local(access.encode(), local_pw)))
    from pnasys_ses import SecureEncryptionService as SES

    SES.CreateEncryptedFile(json.dumps({"computer_id": computer_id}), "cnct_self", local_pw)
    _save_state({"setup_done": True, "computer_id": computer_id})
    for f in (CREDS, ACCESS):
        try:
            os.chmod(f, 0o600)
        except Exception:
            pass
    print(f"Computer ID: {computer_id}")
    print("Setup complete. Vault sealed with TPM (pnasys-ses).")
    _offer_cleanup({str(CREDS), str(ACCESS), str(SAFE / "state.json")})
    return 0


def _input(prompt: str) -> str:
    """input() that treats Ctrl+C / Ctrl+Z and embedded ^C as cancel."""
    try:
        s = input(prompt)
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt
    if "\x03" in s or "\x04" in s:
        raise KeyboardInterrupt
    return s.strip()


def _getpass(prompt: str) -> str:
    """getpass that can't swallow Ctrl+C (Windows msvcrt eats 0x03)."""
    try:
        s = _getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt
    if "\x03" in s or "\x04" in s:
        raise KeyboardInterrupt
    return s


def _unlock() -> tuple[str, dict]:
    """Prompt local pw; return (pw, {"computer_id": ...}). Never prints secrets."""
    from pnasys_ses import SecureEncryptionService as SES

    pw = _getpass("Local encryption password: ")
    try:
        link = json.loads(SES.DecryptEncryptedFile("cnct_link:default", pw))
        print("Vault unlocked (linked).")
        return pw, link
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        pass
    try:
        me = json.loads(SES.DecryptEncryptedFile("cnct_self", pw))
        print("Vault unlocked.")
        return pw, me
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        print("Wrong password or no setup. Run: pnasyscnct setup", file=sys.stderr)
        sys.exit(2)


def cmd_setup_ssh() -> int:
    """Scan for a Pi pairing request, verify, rotate to a fresh link key."""
    pw, me = _unlock()
    computer_id = me.get("computer_id") or L.load_state().get("computer_id", "")
    if not computer_id:
        print("No computer ID. Run: pnasyscnct setup", file=sys.stderr)
        return 2
    print(f"Scanning for Pi pairing requests. Ctrl+C to stop.")
    print(f"YOUR COMPUTER ID (the Pi must type exactly this): {computer_id}")
    req = None
    while req is None:
        try:
            r = L.link_poll(computer_id)
        except KeyboardInterrupt:
            print("\nStopped.")
            return 130
        except Exception as e:
            print(f"scan error, retrying: {e}")
            time.sleep(3)
            continue
        if r.get("empty"):
            continue
        req = r
    print("Pairing request received.")
    dev_name = _input("Device name for this Pi: ") or "default"
    pair_key = _getpass("Pairing encryption key (the one entered on the Pi): ")
    new_key = _getpass("NEW link encryption key (choose now, Pi will adopt it): ")
    if not new_key:
        print("A new link key is required.", file=sys.stderr)
        return 2
    try:
        inner = secure_unpack(pair_key, req["blob"])
        pi_ident = inner["pi_ident"]
    except Exception:
        print("Decrypt failed — wrong pairing key?", file=sys.stderr)
        return 1
    # CHECK-1 (SAS): both humans must see the same code. Pi printed its SAS
    # during `ssh setup`; compare before continuing.
    print(f"CHECK-1 SAS (must match the Pi's screen): {L.sas(pair_key, inner.get('code', ''))}")
    if input("SAS matches? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("Aborted — possible MITM. Start over with a fresh pairing key.", file=sys.stderr)
        return 1
    # CHECK-2 rides along: answer carries code echo + fingerprint; the Pi
    # verifies both, and the server pins the fingerprint for this Pi.
    ans = secure_pack(pair_key, {"computer_id": computer_id, "link_key": new_key,
                                 "code_echo": L.code_echo(inner.get("code", "")),
                                 "ok": True, "ts": int(time.time())})
    r = L.link_answer(computer_id, ans, for_pi=pi_ident)
    if not r.get("ok"):
        print(f"Answer failed: {r}", file=sys.stderr)
        return 1
    L.pc_save_link(computer_id, pi_ident, new_key, pw, name=dev_name)
    print(f"Linked as '{dev_name}'. Pi verified and both sides hold the fresh link key.")
    return 0


def _shell(pi_ident: str, link_key: str) -> int:
    print(f"Remote shell (link {pi_ident[:8]}...). :put local remote | :get remote local | :exit")
    while True:
        try:
            line = input("pi# ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line in (":exit", ":quit"):
            return 0
        try:
            if line.startswith(":put "):
                _, local, remote = line.split(None, 2)
                raw = Path(local).expanduser().read_bytes()
                import base64 as _b64

                op = {"kind": "write", "path": remote, "data_b64": _b64.b64encode(raw).decode()}
                if len(raw) > 4_000_000:
                    print("Large file: streaming in encrypted chunks...")
                    _stream_write(pi_ident, link_key, remote, raw)
                    continue
            elif line.startswith(":get "):
                _, remote, local = line.split(None, 2)
                op = {"kind": "read", "path": remote}
            else:
                op = {"kind": "exec", "cmd": line[:4000]}
            rid = f"sh{int(time.time() * 1000)}"
            blob = secure_pack(link_key, op)
            r = L.enqueue(_access_for(link_key, pi_ident), "secure", {"blob": blob}, rid)
            if not r.get("ok"):
                print(f"send failed: {r.get('error', r)} — retrying...")
                time.sleep(3)
                continue
            res = L.wait_result(pi_ident, rid, 180)
            if res.get("pending"):
                print("(no reply yet — Pi may be offline; result kept, retry :status)")
                continue
            inner = secure_unpack(link_key, res["enc"])
            if inner.get("out"):
                print(inner["out"], end="" if inner["out"].endswith("\n") else "\n")
            if inner.get("data_b64"):
                out = input("save output to local path: ").strip()
                if out:
                    import base64 as _b64

                    Path(out).expanduser().write_bytes(_b64.b64decode(inner["data_b64"]))
                    print(f"saved {out}")
            if inner.get("rc") not in (None, 0):
                print(f"[rc={inner.get('rc')}] {inner.get('err', '')}")
            elif inner.get("error"):
                print(f"Pi error: {inner['error']}")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        except Exception as e:
            print(f"link error ({e}) — reconnecting...")
            time.sleep(3)


def _access_for(link_key: str, pi_ident: str) -> str:
    """Registration check needs the access key — but SSH uses link identity.

    The Pi registered under its access key; pairing stored pi_ident. For
    enqueue auth we send pi_ident as the selector: the server accepts either
    a registered access key or a paired pi_ident for kind=secure.
    """
    return f"ident:{pi_ident}"


def _stream_write(pi_ident: str, link_key: str, remote: str, raw: bytes) -> None:
    from pnasyscnct.common import secure_pack as _sp

    import base64 as _b64

    rid = f"sw{int(time.time() * 1000)}"
    n = 500_000
    parts = [_sp(link_key, {"chunk": _b64.b64encode(raw[i:i + n]).decode()})
             for i in range(0, len(raw), n)] or [_sp(link_key, {"chunk": ""})]
    r = L.enqueue(f"ident:{pi_ident}", "secure",
                  {"blob": _sp(link_key, {"kind": "write-parts", "path": remote,
                                          "parts": parts})}, rid)
    if not r.get("ok"):
        print(f"stream failed: {r.get('error', r)}")
        return
    res = L.wait_result(pi_ident, rid, 300)
    ok = res.get("ok") if isinstance(res, dict) else False
    print(f"streamed {len(raw)} bytes in {len(parts)} encrypted chunks (ok={ok})")


def _tombstone_gate(pi_ident: str, name: str, interactive: bool) -> bool:
    """True if blocked (Pi ran delete). Prompts removal when interactive."""
    try:
        t = L.check_deleted(pi_ident)
    except Exception:
        return False
    if not t.get("deleted"):
        return False
    print(f"Connect failed: this Pi was DELETED on-device at {t.get('ts', '?')}.")
    print("The Pi ran the delete command — its side is wiped and tombstoned.")
    if interactive:
        if input(f"Remove device '{name}' locally? [y/N]: ").strip().lower() in ("y", "yes"):
            _remove_device_local(name)
            print("Removed.")
    else:
        print(f"Run `pnasyscnct delete {name}` to remove it locally.")
    return True


def _remove_device_local(name: str) -> None:
    from pnasys_ses import SecureEncryptionService as SES

    try:
        SES.DeleteEncryptedFile(L._link_slot(name))
    except Exception:
        pass
    st = L.load_state()
    devs = st.get("devices", {})
    devs.pop(name, None)
    st["devices"] = devs
    L.save_state(st)


def _join_verified(link: dict) -> str | None:
    """CHECK-3: join with nonce+fp, verify Pi's ack. Returns error or None."""
    import secrets as _secrets

    nonce = _secrets.token_hex(16)
    fp = L.fingerprint(link["link_key"])
    r = L.ssh_join(link["computer_id"], link["pi_ident"],
                   secure_pack(link["link_key"],
                               {"hello": "pc", "computer_id": link["computer_id"],
                                "nonce": nonce, "ts": int(time.time())}), fp=fp)
    if r.get("_http_error") == 403 or "fingerprint" in str(r.get("error", "")):
        return ("Join rejected: fingerprint mismatch — someone re-keyed this Pi "
                "or a MITM is replaying. Re-pair if you rotated keys.")
    if r.get("_http_error"):
        return f"join http {r.get('_http_error')}"
    deadline = time.time() + 40
    while time.time() < deadline:
        try:
            a = L.ssh_ack_get(link["pi_ident"])
        except Exception as e:
            return f"ack read failed: {e}"
        if a.get("ack"):
            if a["ack"] == L.session_ack(nonce, link["link_key"]):
                return None
            return "Pi ack mismatch — wrong link key or impostor Pi."
        time.sleep(4)
    return "No ack from Pi (offline, or join claim raced — retry)."


def cmd_ssh(name: str = "") -> int:
    import hmac

    pw, _me = _unlock()
    devs = L.pc_devices()
    if name:
        if name not in devs:
            print(f"Unknown device '{name}'. Linked: {', '.join(sorted(devs)) or 'none'}.",
                  file=sys.stderr)
            return 2
    elif len(devs) == 1:
        name = next(iter(devs))
    else:
        print(f"Choose a device: {', '.join(sorted(devs)) or 'none linked'}.", file=sys.stderr)
        return 2
    try:
        link = L.pc_load_link(pw, name)
    except Exception:
        print("Vault entry missing. Re-link with: pnasyscnct setup --ssh", file=sys.stderr)
        return 2
    if _tombstone_gate(link["pi_ident"], name, interactive=True):
        return 1
    typed = _getpass("Link encryption key: ")
    if not typed or not hmac.compare_digest(typed, link["link_key"]):
        print("Wrong encryption key.", file=sys.stderr)
        return 1
    del typed
    err = _join_verified(link)
    if err:
        print(f"Session failed: {err}", file=sys.stderr)
        return 1
    print(f"Session open to '{name}' (mutually verified). Reconnects automatically.")
    while True:
        rc = _shell(link["pi_ident"], link["link_key"])
        if rc == 0:
            return 0
        print("Shell exited abnormally — rejoining in 5s (Ctrl+C to quit)...")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            return 130


def cmd_delete(name: str = "") -> int:
    pw, _me = _unlock()
    devs = L.pc_devices()
    if not name:
        print(f"Usage: pnasyscnct delete <device>. Linked: {', '.join(sorted(devs)) or 'none'}.",
              file=sys.stderr)
        return 2
    if name not in devs:
        print(f"Unknown device '{name}'.", file=sys.stderr)
        return 2
    meta = devs[name]
    try:
        link = L.pc_load_link(pw, name)
        fp = L.fingerprint(link["link_key"])
    except Exception:
        fp = ""
    if input(f"Delete device '{name}' (local files + GitHub queue/presence)? [y/N]: "
             ).strip().lower() not in ("y", "yes"):
        print("Aborted.")
        return 2
    try:
        r = L.purge(meta["pi_ident"], fp=fp)
        print(f"GitHub purge: {'ok' if r.get('ok') else r}")
    except Exception as e:
        print(f"Purge failed: {e}", file=sys.stderr)
    _remove_device_local(name)
    print(f"Device '{name}' deleted.")
    return 0


def cmd_clearconnections() -> int:
    pw, _me = _unlock()
    devs = L.pc_devices()
    if not devs:
        print("No connections.")
        return 0
    print(f"This drops ALL connections: {', '.join(sorted(devs))}")
    if input("Type YES to confirm: ").strip() != "YES":
        print("Aborted.")
        return 2
    for name in sorted(devs):
        try:
            link = L.pc_load_link(pw, name)
            fp = L.fingerprint(link["link_key"])
            pi = link["pi_ident"]
        except Exception:
            fp, pi = "", devs[name].get("pi_ident", "")
        try:
            if pi:
                L.purge(pi, fp=fp)
        except Exception as e:
            print(f"purge {name} failed: {e}")
        _remove_device_local(name)
        print(f"  cleared {name}")
    print("All connections cleared.")
    return 0


def cmd_update() -> int:
    import shutil
    import subprocess
    import tempfile
    import urllib.request

    if sys.platform == "win32" or shutil.which("bash") is None:
        # No usable bash: upgrade straight from PyPI (identical package).
        print("Updating pnasyscnct from PyPI ...")
        return subprocess.run([sys.executable, "-m", "pip", "install", "-U",
                               "pnasyscnct"]).returncode
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
    except FileNotFoundError:
        print("bash not found (Windows: use the installer from GitHub instead).", file=sys.stderr)
        return 1
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def cmd_mcp(enckey: str, sshdev: str = "") -> int:
    from pnasyscnct.mcp_server import serve

    devs = L.pc_devices()
    if sshdev:
        if sshdev not in devs:
            print(f"Unknown device '{sshdev}'. Linked: {', '.join(sorted(devs)) or 'none'}.",
                  file=sys.stderr)
            return 2
    elif len(devs) == 1:
        sshdev = next(iter(devs))
    else:
        print("Pass --sshdev DEVICE. Linked: " f"{', '.join(sorted(devs)) or 'none'}.",
              file=sys.stderr)
        return 2
    if not enckey:
        print("--enckey (the link encryption key) is required.", file=sys.stderr)
        return 2
    meta = devs[sshdev]
    print(f"MCP server starting for '{sshdev}' (SSH session active).", file=sys.stderr)
    serve(link_key=enckey, pi_ident=meta["pi_ident"], computer_id=meta["computer_id"])
    return 0


def cmd_selftest() -> int:
    pw = "selftest-pw"
    key, iv = derive_key_iv(pw)
    assert len(key) == 32 and len(iv) == 12
    b = encrypt_local(b"hello-pc", pw)
    assert decrypt_local(b, pw) == b"hello-pc"
    sk = generate_session_key()
    assert len(sk.split("=")) == 6
    blob = secure_pack("k", {"kind": "exec", "cmd": "x"})
    assert secure_unpack("k", blob)["cmd"] == "x"
    print("selftest OK: AES vault, session keygen, secure pack/unpack")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        return _dispatch(argv)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130


def _dispatch(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("Usage: pnasyscnct {setup [--ssh]|ssh [DEVICE]|mcp --enckey KEY [--sshdev DEV]|selftest|update|delete DEVICE|clearconnections}")
        return 0
    if argv[0] == "setup" and "--ssh" in argv[1:]:
        return cmd_setup_ssh()
    if argv[0] == "setup":
        return cmd_setup()
    if argv[0] == "ssh":
        rest = [a for a in argv[1:] if not a.startswith("-")]
        return cmd_ssh(rest[0] if rest else "")
    if argv[0] == "delete":
        rest = [a for a in argv[1:] if not a.startswith("-")]
        return cmd_delete(rest[0] if rest else "")
    if argv[0] == "clearconnections":
        return cmd_clearconnections()
    if argv[0] == "update":
        return cmd_update()
    if argv[0] == "mcp":
        key, dev = "", ""
        rest = argv[1:]
        for i, a in enumerate(rest):
            if a == "--enckey" and i + 1 < len(rest):
                key = rest[i + 1]
            if a == "--sshdev" and i + 1 < len(rest):
                dev = rest[i + 1]
        return cmd_mcp(key, dev)
    if argv[0] == "selftest":
        return cmd_selftest()
    print(f"Unknown command: {argv[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
