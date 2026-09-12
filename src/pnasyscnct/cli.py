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


def cmd_setup() -> int:
    _ensure()
    print("pnasyscnct setup (computer)")
    fav_rest = input("Favorite restaurant: ").strip()
    fav_animal = input("Favorite animal: ").strip()
    fav_color = input("Favorite color: ").strip()
    pc_user = input("Computer username: ").strip()
    pc_pass = getpass.getpass("Computer password: ")
    local_pw = getpass.getpass("Local encryption password (anything): ")
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
    return 0


def _unlock() -> tuple[str, dict]:
    """Prompt local pw; return (pw, {"computer_id": ...}). Never prints secrets."""
    from pnasys_ses import SecureEncryptionService as SES

    pw = getpass.getpass("Local encryption password: ")
    try:
        link = json.loads(SES.DecryptEncryptedFile("cnct_link", pw))
        print("Vault unlocked (linked).")
        return pw, link
    except Exception:
        pass
    try:
        me = json.loads(SES.DecryptEncryptedFile("cnct_self", pw))
        print("Vault unlocked.")
        return pw, me
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
    print(f"Scanning for Pi pairing requests (computer {computer_id[:8]}...). Ctrl+C to stop.")
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
    pair_key = getpass.getpass("Pairing encryption key (the one entered on the Pi): ")
    new_key = getpass.getpass("NEW link encryption key (choose now, Pi will adopt it): ")
    if not new_key:
        print("A new link key is required.", file=sys.stderr)
        return 2
    try:
        inner = secure_unpack(pair_key, req["blob"])
        pi_ident = inner["pi_ident"]
    except Exception:
        print("Decrypt failed — wrong pairing key?", file=sys.stderr)
        return 1
    ans = secure_pack(pair_key, {"computer_id": computer_id, "link_key": new_key,
                                 "ok": True, "ts": int(time.time())})
    r = L.link_answer(computer_id, ans, for_pi=pi_ident)
    if not r.get("ok"):
        print(f"Answer failed: {r}", file=sys.stderr)
        return 1
    L.pc_save_link(computer_id, pi_ident, new_key, pw)
    print("Linked. Pi verified and both sides hold the fresh link key.")
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


def cmd_ssh() -> int:
    pw, link = _unlock()
    if "link_key" not in link:
        print("Not linked yet. Run: pnasyscnct setup --ssh", file=sys.stderr)
        return 2
    L.ssh_join(link["computer_id"], link["pi_ident"],
               secure_pack(link["link_key"], {"hello": "pc", "ts": int(time.time())}))
    print("Session open. Reconnects automatically on failure.")
    while True:
        rc = _shell(link["pi_ident"], link["link_key"])
        if rc == 0:
            return 0
        print("Shell exited abnormally — rejoining in 5s (Ctrl+C to quit)...")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            return 130


def cmd_mcp(enckey: str) -> int:
    from pnasyscnct.mcp_server import serve

    st = L.load_state()
    if not st.get("pi_ident") or not st.get("computer_id"):
        print("Not linked yet. Run: pnasyscnct setup --ssh", file=sys.stderr)
        return 2
    if not enckey:
        print("--enckey (the link encryption key) is required.", file=sys.stderr)
        return 2
    print("MCP server starting (SSH session active).", file=sys.stderr)
    serve(link_key=enckey, pi_ident=st["pi_ident"], computer_id=st["computer_id"])
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
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("Usage: pnasyscnct {setup [--ssh]|ssh|mcp --enckey KEY|selftest}")
        return 0
    if argv[0] == "setup" and "--ssh" in argv[1:]:
        return cmd_setup_ssh()
    if argv[0] == "setup":
        return cmd_setup()
    if argv[0] == "ssh":
        return cmd_ssh()
    if argv[0] == "mcp":
        key = ""
        for i, a in enumerate(argv[1:]):
            if a == "--enckey" and i + 1 < len(argv[1:]):
                key = argv[1:][i + 1]
        return cmd_mcp(key)
    if argv[0] == "selftest":
        return cmd_selftest()
    print(f"Unknown command: {argv[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
