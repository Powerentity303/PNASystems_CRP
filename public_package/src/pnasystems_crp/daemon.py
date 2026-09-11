"""Background listening server for PNASystems_CRP (Pi 4/5, headless or desktop).

enable  -> systemd user service (or nohup fallback), polls queue repo for
           oldest request matching sha256(access_key), executes, responds,
           supports 'prepare for stream' + chunked stream API.
disable -> stops the service.

Idle rule: if no new event is claimed for 10 minutes, the listener
disables itself (stop_daemon) and exits.

Secure jobs (kind "secure", opaque pnasys-encrypted blob) are decrypted
with the channel key from setup; the plaintext op never leaves the Pi.

Poll loop never prints the access key. Reconnects with backoff on errors.
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

SERVICE_NAME = "pnasyscrp-listener"
IDLE_SECONDS = 600
HOME = Path.home()
SAFE_DIR = HOME / ".pnasys_crp"
VAULT = SAFE_DIR / ".vault"
STATE = SAFE_DIR / "state.json"
PIDFILE = SAFE_DIR / "listener.pid"
ENVFILE = VAULT / "listener.env"  # PNASYS_PW=..., mode 600 (user service only)
LAST_EVENT = SAFE_DIR / "last_event"  # unix ts of last claimed job / enable
SESSION_FILE = VAULT / "session.key"  # enable-time session key, 600


def _vercel_base() -> str:
    try:
        s = json.loads(STATE.read_text())
        return s.get("vercel_base") or os.environ.get("PNASYS_VERCEL_BASE", "")
    except Exception:
        return os.environ.get("PNASYS_VERCEL_BASE", "")


def _touch_event() -> None:
    try:
        LAST_EVENT.write_text(str(int(time.time())))
    except Exception:
        pass


def _idle_for() -> float:
    try:
        return time.time() - int(LAST_EVENT.read_text().strip())
    except Exception:
        return 0.0


def _load_session_key() -> str | None:
    """Read the enable-time session key (600 file, Pi-local)."""
    try:
        key = SESSION_FILE.read_text().strip()
        return key or None
    except Exception:
        return None


def _pack_response(session_key: str, resp: dict) -> dict:
    """Encrypt a response dict with pnasys under the session key.

    Vercel stores/transports this blob opaquely; only the MCP side (which
    holds the same session key) can decrypt it. Large reads are encrypted
    as base64 inside the same envelope — GitHub chunking + result
    streaming already handle arbitrary sizes downstream.
    """
    import base64 as _b64
    import json as _json

    try:
        from .crypto_local import secure_pack
    except ImportError:
        from pnasystems_crp.crypto_local import secure_pack  # type: ignore[no-redef]
    raw = resp.pop("_stream_raw", None)
    if raw is not None:
        resp = dict(resp)
        resp["data_b64"] = _b64.b64encode(raw).decode("ascii")
        resp["stream"] = True
    return {"id": resp.get("id", ""), "enc": secure_pack(session_key, resp)}


def _run_exec(msg: dict) -> dict:
    out = subprocess.run(msg.get("cmd", "echo ok"), shell=True, capture_output=True,
                         text=True, timeout=120)
    return {"id": msg.get("id", ""), "rc": out.returncode,
            "out": out.stdout[-20000:], "err": out.stderr[-20000:]}


def _run_read(msg: dict) -> dict:
    rid = msg.get("id", "")
    p = Path(msg.get("path", ""))
    try:
        raw = p.read_bytes()
    except Exception as e:
        return {"id": rid, "error": f"read failed: {e}"}
    if len(raw) > 5_000_000:
        return {"id": rid, "stream": True, "note": "prepare for stream",
                "_stream_raw": raw}
    return {"id": rid, "ok": True, "data_b64": base64.b64encode(raw).decode()}


def _run_write(msg: dict) -> dict:
    rid = msg.get("id", "")
    p = Path(msg.get("path", "/tmp/pnasys_out.bin"))
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = base64.b64decode(msg.get("data_b64", "")) if msg.get("data_b64") else b""
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


def _dispatch(msg: dict) -> dict | None:
    """Route a job to its handler. Returns response dict, or None to skip."""
    kind = msg.get("kind", "")
    if kind == "exec":
        return _run_exec(msg)
    if kind == "read":
        return _run_read(msg)
    if kind == "write":
        return _run_write(msg)
    if kind == "install":
        return _run_install(msg)
    if kind == "secure":
        session = _load_session_key()
        if session is None:
            return {"id": msg.get("id", ""), "error": "no session key on pi (re-run enable)"}
        try:
            try:
                from .crypto_local import secure_pack, secure_unpack
            except ImportError:
                from pnasystems_crp.crypto_local import secure_pack, secure_unpack  # type: ignore[no-redef]
            op = secure_unpack(session, str(msg.get("blob", "")))
        except Exception:
            return {"id": msg.get("id", ""), "error": "secure decrypt failed"}
        if not isinstance(op, dict) or op.get("kind") in (None, "secure"):
            return {"id": msg.get("id", ""), "error": "bad secure op"}
        op = dict(op)
        op["id"] = msg.get("id", "")
        resp = _dispatch(op)
        if resp is None:
            return {"id": msg.get("id", ""), "error": "unsupported op"}
        # Pi encrypts its response: Vercel stores it blind, MCP decrypts it.
        return _pack_response(session, resp)
    return None


def _poll_once(access_key: str, base: str) -> bool:
    """Poll once. Returns True if an event was claimed (resets idle timer)."""
    ident = hashlib.sha256(access_key.encode()).hexdigest()
    url = base.rstrip("/") + f"/api/poll?ident={ident}"
    try:
        with urllib.request.urlopen(url, timeout=40) as r:
            msg = json.loads(r.read().decode())
    except Exception:
        return False
    if not msg or msg.get("empty"):
        return False
    _touch_event()
    try:
        resp = _dispatch(msg)
        if resp is None:
            return True
        if resp.pop("_stream_raw", None) is not None:
            raw = resp.pop("_stream_raw")
            _respond(base, ident, {"id": resp.get("id", ""), "stream": True,
                                   "note": "prepare for stream"})
            _stream_back(base, ident, str(resp.get("id", "")), raw)
            return True
        # read-op large payloads use the same stream handshake
        if msg.get("kind") == "read" and resp.get("data_b64") and len(resp["data_b64"]) > 6_000_000:
            raw = base64.b64decode(resp["data_b64"])
            _respond(base, ident, {"id": resp.get("id", ""), "stream": True,
                                   "note": "prepare for stream"})
            _stream_back(base, ident, str(resp.get("id", "")), raw)
            return True
        _respond(base, ident, resp)
    except Exception:
        pass
    return True


def _respond(base: str, ident: str, payload: dict) -> None:
    try:
        data = json.dumps({"ident": ident, **payload}).encode()
        req = urllib.request.Request(base.rstrip("/") + "/api/respond", data=data,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=25).read()
    except Exception:
        pass


def _stream_back(base: str, ident: str, req_id: str, raw: bytes, chunk: int = 700_000) -> None:
    for i in range(0, len(raw), chunk):
        part = base64.b64encode(raw[i:i + chunk]).decode()
        payload = json.dumps({"ident": ident, "id": req_id, "seq": i // chunk,
                              "data_b64": part, "last": i + chunk >= len(raw)}).encode()
        for attempt in range(5):
            try:
                req = urllib.request.Request(base.rstrip("/") + "/api/stream", data=payload,
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=25).read()
                break
            except Exception:
                time.sleep(2 * (attempt + 1))


def run_forever(access_key: str) -> None:
    base = _vercel_base()
    if not base:
        print("No vercel base configured", file=sys.stderr)
        sys.exit(2)
    backoff = 5
    while True:
        try:
            _poll_once(access_key, base)
            backoff = 5
        except Exception:
            time.sleep(backoff)
            backoff = min(120, backoff * 2)
            continue
        if _idle_for() > IDLE_SECONDS:
            try:
                stop_daemon()
            finally:
                sys.exit(0)
        time.sleep(5)


def _write_env_file(pw: str) -> None:
    VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ENVFILE.write_text(f"PNASYS_PW={pw}\n")
    try:
        os.chmod(ENVFILE, 0o600)
    except Exception:
        pass


def start_daemon(pw: str) -> int:
    """Start listener. pw unlocks the vault for the background service."""
    _write_env_file(pw)
    _touch_event()
    unit = (
        "[Unit]\n"
        "Description=PNASystems CRP listener (Pi 4/5)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "[Service]\n"
        f"ExecStart={sys.executable} -m pnasystems_crp.daemon_run\n"
        f"EnvironmentFile={ENVFILE}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    try:
        sysd = HOME / ".config" / "systemd" / "user"
        sysd.mkdir(parents=True, exist_ok=True)
        (sysd / f"{SERVICE_NAME}.service").write_text(unit)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        r = subprocess.run(["systemctl", "--user", "enable", "--now", SERVICE_NAME])
        subprocess.run(["loginctl", "enable-linger"], check=False)
        if r.returncode == 0:
            print("Listener enabled (systemd user service).")
            return 0
        print("systemd enable failed, using nohup fallback", file=sys.stderr)
    except Exception as e:
        print(f"systemd failed ({e}), using nohup fallback", file=sys.stderr)
    env = dict(os.environ, PNASYS_PW=pw)
    proc = subprocess.Popen([sys.executable, "-m", "pnasystems_crp.daemon_run"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True, env=env)
    PIDFILE.write_text(str(proc.pid))
    print(f"Listener enabled (pid {proc.pid}).")
    return 0


def stop_daemon() -> int:
    subprocess.run(["systemctl", "--user", "disable", "--now", SERVICE_NAME], check=False)
    try:
        if PIDFILE.exists():
            pid = int(PIDFILE.read_text().strip())
            os.kill(pid, 15)
            PIDFILE.unlink(missing_ok=True)
    except Exception:
        pass
    print("Listener disabled.")
    return 0
