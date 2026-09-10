"""Background listening server for PNASystems_CRP (Pi 4/5, headless or desktop).

enable  -> systemd user service (or nohup fallback), polls queue repo for
           oldest request matching sha256(access_key), executes, responds,
           supports 'prepare for stream' + chunked stream API.
disable -> stops the service.

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
HOME = Path.home()
SAFE_DIR = HOME / ".pnasys_crp"
VAULT = SAFE_DIR / ".vault"
STATE = SAFE_DIR / "state.json"
PIDFILE = SAFE_DIR / "listener.pid"
ENVFILE = VAULT / "listener.env"  # PNASYS_PW=..., mode 600 (user service only)


def _vercel_base() -> str:
    try:
        s = json.loads(STATE.read_text())
        return s.get("vercel_base") or os.environ.get("PNASYS_VERCEL_BASE", "")
    except Exception:
        return os.environ.get("PNASYS_VERCEL_BASE", "")


def _poll_once(access_key: str, base: str) -> None:
    # Identify as sha256(access_key); server maps to queue files
    # named <hash>-<rand7>.json (rand suffix avoids same-name collisions).
    ident = hashlib.sha256(access_key.encode()).hexdigest()
    url = base.rstrip("/") + f"/api/poll?ident={ident}"
    try:
        with urllib.request.urlopen(url, timeout=25) as r:
            msg = json.loads(r.read().decode())
    except Exception:
        return
    if not msg or msg.get("empty"):
        return
    req_id = msg.get("id", "")
    kind = msg.get("kind", "")
    try:
        if kind == "exec":
            out = subprocess.run(
                msg.get("cmd", "echo ok"),
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            _respond(base, ident, {"id": req_id, "rc": out.returncode,
                                   "out": out.stdout[-20000:], "err": out.stderr[-20000:]})
        elif kind == "read":
            p = Path(msg.get("path", ""))
            try:
                raw = p.read_bytes()
            except Exception as e:
                _respond(base, ident, {"id": req_id, "error": f"read failed: {e}"})
                return
            if len(raw) > 5_000_000:
                _respond(base, ident, {"id": req_id, "stream": True, "note": "prepare for stream"})
                _stream_back(base, ident, req_id, raw)
            else:
                _respond(base, ident, {"id": req_id, "ok": True,
                                       "data_b64": base64.b64encode(raw).decode()})
        elif kind == "write":
            p = Path(msg.get("path", "/tmp/pnasys_out.bin"))
            p.parent.mkdir(parents=True, exist_ok=True)
            data = msg.get("data_b64", "")
            raw = base64.b64decode(data) if data else b""
            p.write_bytes(raw)
            _respond(base, ident, {"id": req_id, "ok": True, "path": str(p),
                                   "bytes": len(raw)})
        elif kind == "install":
            pkg = "".join(c for c in str(msg.get("pkg", "")) if c.isalnum() or c in "-+._")
            if not pkg:
                _respond(base, ident, {"id": req_id, "error": "empty package"})
                return
            out = subprocess.run(
                ["sudo", "apt-get", "install", "-y", pkg],
                capture_output=True, text=True, timeout=600,
            )
            _respond(base, ident, {"id": req_id, "rc": out.returncode,
                                   "out": out.stdout[-20000:], "err": out.stderr[-20000:]})
    except Exception:
        return


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
        time.sleep(5)


def _write_env_file(pw: str) -> None:
    VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Quote for systemd EnvironmentFile (KEY=val, no spaces in pw handling).
    ENVFILE.write_text(f'PNASYS_PW={pw}\n')
    try:
        os.chmod(ENVFILE, 0o600)
    except Exception:
        pass


def start_daemon(pw: str) -> int:
    """Start listener. pw unlocks the vault for the background service."""
    _write_env_file(pw)
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
