"""Pi listener: secure queue jobs (session or link key) + SSH presence.

- Plain kinds (exec/read/write/install) as before; secure blobs try the
  session key, then the link key. Responses are pnasys-packed with the key
  that opened them — Vercel stays blind.
- Exec runs root-aware: sudo -n when not uid 0 (needs NOPASSWD or a root
  listener), else direct shell.
- Idle rule: no claimed event for 10 min -> self-disable + exit.
- run_ssh_presence(pw): heartbeat + join-watch + queue loop for ssh sessions.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from pnasyscnct import link as L
from pnasyscnct.common import secure_pack, secure_unpack

SERVICE = "pnasyscnct-listener"
HOME = Path.home()
SAFE = HOME / ".pnasys_crp"
VAULT = SAFE / ".vault"
STATE = SAFE / "state.json"
PIDFILE = SAFE / "listener.pid"
ENVFILE = VAULT / "listener.env"
LAST_EVENT = SAFE / "last_event"
SESSION = VAULT / "session.key"
IDLE_SECONDS = 600


def _touch() -> None:
    try:
        LAST_EVENT.write_text(str(int(time.time())))
    except Exception:
        pass


def _idle() -> float:
    try:
        return time.time() - int(LAST_EVENT.read_text().strip())
    except Exception:
        return 0.0


def _keys(pw: str) -> list[str]:
    """Session key and/or link key, best-effort. Never printed."""
    keys: list[str] = []
    try:
        sk = SESSION.read_text().strip()
        if sk:
            keys.append(sk)
    except Exception:
        pass
    try:
        keys.append(L.pi_load_link(pw)["link_key"])
    except Exception:
        pass
    return keys


def _as_root(cmd: str) -> str:
    try:
        if os.geteuid() == 0:
            return cmd
    except AttributeError:
        pass
    return f"sudo -n {cmd}"


def _run_exec(msg: dict) -> dict:
    out = subprocess.run(_as_root(msg.get("cmd", "echo ok")), shell=True,
                         capture_output=True, text=True, timeout=120)
    return {"id": msg.get("id", ""), "rc": out.returncode,
            "out": out.stdout[-20000:], "err": out.stderr[-20000:]}


def _run_read(msg: dict) -> dict:
    rid = msg.get("id", "")
    try:
        raw = Path(msg.get("path", "")).read_bytes()
    except Exception as e:
        return {"id": rid, "error": f"read failed: {e}"}
    if len(raw) > 5_000_000:
        return {"id": rid, "_stream_raw": raw}
    return {"id": rid, "ok": True, "data_b64": base64.b64encode(raw).decode()}


def _run_write(msg: dict) -> dict:
    rid = msg.get("id", "")
    p = Path(msg.get("path", "/tmp/pnasys_out.bin"))
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = base64.b64decode(msg.get("data_b64", "")) if msg.get("data_b64") else b""
    p.write_bytes(raw)
    return {"id": rid, "ok": True, "path": str(p), "bytes": len(raw)}


def _run_write_parts(msg: dict, key: str) -> dict:
    """Assemble one secure job carrying many encrypted chunks (no ordering risk)."""
    import base64 as _b64

    rid = msg.get("id", "")
    p = Path(msg.get("path", "/tmp/pnasys_out.bin"))
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        from pnasyscnct.common import secure_unpack as _su

        raw = b"".join(_b64.b64decode(_su(key, tok)["chunk"]) for tok in msg.get("parts", []))
    except Exception:
        return {"id": rid, "error": "chunk decrypt failed"}
    p.write_bytes(raw)
    return {"id": rid, "ok": True, "path": str(p), "bytes": len(raw)}


def _run_install(msg: dict) -> dict:
    rid = msg.get("id", "")
    pkg = "".join(c for c in str(msg.get("pkg", "")) if c.isalnum() or c in "-+._")
    if not pkg:
        return {"id": rid, "error": "empty package"}
    out = subprocess.run(["sudo", "apt-get", "install", "-y", pkg],
                         capture_output=True, text=True, timeout=600)
    return {"id": rid, "rc": out.returncode,
            "out": out.stdout[-20000:], "err": out.stderr[-20000:]}


def _pack(key: str, resp: dict) -> dict:
    raw = resp.pop("_stream_raw", None)
    if raw is not None:
        resp = dict(resp)
        resp["data_b64"] = base64.b64encode(raw).decode("ascii")
        resp["stream"] = True
    return {"id": resp.get("id", ""), "enc": secure_pack(key, resp)}


def _dispatch(msg: dict, keys: list[str], _key: str = "") -> dict | None:
    kind = msg.get("kind", "")
    if kind == "exec":
        return _run_exec(msg)
    if kind == "read":
        return _run_read(msg)
    if kind == "write":
        return _run_write(msg)
    if kind == "write-parts":
        return _run_write_parts(msg, _key or (keys[0] if keys else ""))
    if kind == "install":
        return _run_install(msg)
    if kind == "secure":
        for key in keys:
            try:
                op = secure_unpack(key, str(msg.get("blob", "")))
            except Exception:
                continue
            if not isinstance(op, dict) or op.get("kind") in (None, "secure"):
                return {"id": msg.get("id", ""), "error": "bad secure op"}
            op = dict(op)
            op["id"] = msg.get("id", "")
            resp = _dispatch(op, keys, _key=key)
            if resp is None:
                return {"id": msg.get("id", ""), "error": "unsupported op"}
            return _pack(key, resp)
        return {"id": msg.get("id", ""), "error": "secure decrypt failed"}
    return None


def _respond(base: str, ident: str, payload: dict) -> None:
    try:
        data = json.dumps({"ident": ident, **payload}).encode()
        req = urllib.request.Request(base.rstrip("/") + "/api/respond", data=data,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=25).read()
    except Exception:
        pass


def _stream_back(base: str, ident: str, rid: str, key: str, raw: bytes) -> None:
    # Encrypted chunks, one pnasys token per stream part.
    n = 500_000
    parts = [raw[i:i + n] for i in range(0, len(raw), n)] or [b""]
    import base64 as _b64

    for i, part in enumerate(parts):
        payload = json.dumps({"ident": ident, "id": rid, "seq": i,
                              "data_b64": secure_pack(key, {"chunk": _b64.b64encode(part).decode()}),
                              "last": i == len(parts) - 1}).encode()
        for attempt in range(5):
            try:
                req = urllib.request.Request(base.rstrip("/") + "/api/stream", data=payload,
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=25).read()
                break
            except Exception:
                time.sleep(2 * (attempt + 1))


def _poll_once(access_key: str, pw: str, base: str) -> bool:
    ident = hashlib.sha256(access_key.encode()).hexdigest()
    url = base.rstrip("/") + f"/api/poll?ident={ident}"
    try:
        with urllib.request.urlopen(url, timeout=40) as r:
            msg = json.loads(r.read().decode())
    except Exception:
        return False
    if not msg or msg.get("empty"):
        return False
    _touch()
    try:
        resp = _dispatch(msg, _keys(pw))
        if resp is None:
            return True
        if resp.get("enc") is not None:  # already encrypted envelope
            _respond(base, ident, resp)
            return True
        raw = resp.pop("_stream_raw", None)
        if raw is not None:
            _respond(base, ident, {"id": resp.get("id", ""), "stream": True,
                                   "note": "prepare for stream"})
            # plaintext stream path (legacy); secure reads encrypt instead
            for i in range(0, len(raw), 700_000):
                part = base64.b64encode(raw[i:i + 700_000]).decode()
                payload = json.dumps({"ident": ident, "id": resp.get("id", ""), "seq": i // 700_000,
                                      "data_b64": part, "last": i + 700_000 >= len(raw)}).encode()
                req = urllib.request.Request(base.rstrip("/") + "/api/stream", data=payload,
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=25).read()
            return True
        _respond(base, ident, resp)
    except Exception:
        pass
    return True


def _loop(access_key: str, pw: str, base: str, heartbeat: dict | None = None) -> None:
    backoff, ticks = 5, 0
    while True:
        try:
            _poll_once(access_key, pw, base)
            backoff = 5
        except Exception:
            time.sleep(backoff)
            backoff = min(120, backoff * 2)
            continue
        ticks += 1
        if heartbeat is not None and ticks % 6 == 0:
            try:
                L.ssh_hello(heartbeat["pi_ident"],
                            secure_pack(heartbeat["key"], {"hb": int(time.time())}))
            except Exception:
                pass
        if _idle() > IDLE_SECONDS:
            try:
                stop_daemon()
            finally:
                sys.exit(0)
        time.sleep(5)


def _load_access_pw():
    import getpass

    pw = os.environ.get("PNASYS_PW") or (getpass.getpass("Local encryption password: ")
                                         if os.isatty(0) else "")
    if not pw:
        raise SystemExit("PNASYS_PW not set for background service")
    from pnasyscnct.common import decrypt_local

    bundle = json.loads((VAULT / "access.enc.json").read_text())
    return decrypt_local(bundle, pw).decode(), pw


def run_forever() -> None:
    base = L.load_state().get("vercel_base") or os.environ.get("PNASYS_VERCEL_BASE", "")
    access, pw = _load_access_pw()
    _loop(access, pw, base)


def _watch_join(pi_ident: str, link: dict) -> None:
    """Claim a computer join, verify it, post the session ack.

    Verifies (CHECK-3): blob decrypts with the link key, computer_id matches
    the link record, timestamp is fresh (anti-replay). The ack proves Pi-side
    key possession without revealing the key.
    """
    import urllib.request as _url

    url = L.base().rstrip("/") + f"/api/ssh/wait?pi_ident={pi_ident}"
    try:
        with _url.urlopen(url, timeout=65) as r:
            join = json.loads(r.read().decode())
    except Exception:
        return
    if not join or join.get("empty"):
        return
    _touch()
    try:
        inner = secure_unpack(link["link_key"], join["blob"])
        assert inner.get("computer_id") == link["computer_id"]
        assert abs(int(time.time()) - int(inner.get("ts", 0))) <= 300
        nonce = str(inner["nonce"])
    except Exception:
        return
    try:
        L.ssh_ack_post(pi_ident, L.session_ack(nonce, link["link_key"]))
        print(f"Session verified for computer {link['computer_id'][:8]}...")
    except Exception:
        pass


def run_ssh_presence(pw: str) -> int:
    from pnasyscnct.common import decrypt_local

    base = L.load_state().get("vercel_base") or os.environ.get("PNASYS_VERCEL_BASE", "")
    access = decrypt_local(json.loads((VAULT / "access.enc.json").read_text()), pw).decode()
    try:
        link = L.pi_load_link(pw)
    except Exception:
        print("Not linked.", file=sys.stderr)
        return 2
    pi_ident = hashlib.sha256(access.encode()).hexdigest()
    print("Announcing presence; join-watch + queue listener active.")
    backoff, ticks = 5, 0
    while True:
        try:
            _poll_once(access, pw, base)
            backoff = 5
        except Exception:
            time.sleep(backoff)
            backoff = min(120, backoff * 2)
            continue
        ticks += 1
        if ticks % 6 == 0:
            try:
                L.ssh_hello(pi_ident, secure_pack(link["link_key"],
                                                  {"hb": int(time.time())}))
            except Exception:
                pass
            _watch_join(pi_ident, link)
        if _idle() > IDLE_SECONDS:
            try:
                stop_daemon()
            finally:
                sys.exit(0)
        time.sleep(5)
    return 0


def start_daemon(pw: str) -> int:
    VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)
    (VAULT / "listener.env").write_text(f"PNASYS_PW={pw}\n")
    try:
        os.chmod(VAULT / "listener.env", 0o600)
    except Exception:
        pass
    _touch()
    unit = ("[Unit]\nDescription=PNASystems Connect listener (Pi)\n"
            "After=network-online.target\nWants=network-online.target\n[Service]\n"
            f"ExecStart={sys.executable} -m pnasyscnct.pi_daemon_run\n"
            f"EnvironmentFile={VAULT / 'listener.env'}\n"
            "Restart=always\nRestartSec=5\n[Install]\nWantedBy=default.target\n")
    try:
        sysd = HOME / ".config" / "systemd" / "user"
        sysd.mkdir(parents=True, exist_ok=True)
        (sysd / f"{SERVICE}.service").write_text(unit)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        r = subprocess.run(["systemctl", "--user", "enable", "--now", SERVICE])
        subprocess.run(["loginctl", "enable-linger"], check=False)
        if r.returncode == 0:
            print("Listener enabled (systemd user service).")
            return 0
    except Exception as e:
        print(f"systemd failed ({e}), using nohup fallback", file=sys.stderr)
    env = dict(os.environ, PNASYS_PW=pw)
    proc = subprocess.Popen([sys.executable, "-m", "pnasyscnct.pi_daemon_run"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True, env=env)
    (SAFE / "listener.pid").write_text(str(proc.pid))
    print(f"Listener enabled (pid {proc.pid}).")
    return 0


def stop_daemon() -> int:
    subprocess.run(["systemctl", "--user", "disable", "--now", SERVICE], check=False)
    try:
        pidfile = SAFE / "listener.pid"
        if pidfile.exists():
            os.kill(int(pidfile.read_text().strip()), 15)
            pidfile.unlink(missing_ok=True)
    except Exception:
        pass
    print("Listener disabled.")
    return 0


if __name__ == "__main__":
    run_forever()
