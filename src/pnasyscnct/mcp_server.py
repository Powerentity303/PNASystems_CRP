"""MCP server for pnasyscnct — stdio, stdlib-only transport (no mcp dep).

Launched as: pnasyscnct mcp --enckey "<link key>" --sshdev "<device>"
Keys live at launch (link key flag, device ids from link state); tool calls
carry only op arguments. SSH session is (re)established automatically and
kept active with reconnects. NEVER write to stdout except protocol replies.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
import time

from pnasyscnct import link as L
from pnasyscnct.common import secure_pack, secure_unpack
from pnasyscnct import __version__

logger = logging.getLogger(__name__)

LINK_KEY = ""
PI_IDENT = ""
COMPUTER_ID = ""


def _send(op: dict, rid: str | None = None) -> dict:
    rid = rid or f"mcp{int(time.time() * 1000)}"
    blob = secure_pack(LINK_KEY, op)
    return L.api("POST", "/api/request",
                 {"access_key": f"ident:{PI_IDENT}", "kind": "secure",
                  "blob": blob, "id": rid})


def _collect(rid: str, wait_s: int) -> str:
    deadline = time.time() + max(5, min(wait_s, 300))
    while time.time() < deadline:
        r = L.fetch_result(PI_IDENT, rid)
        if r.get("pending"):
            time.sleep(5)
            continue
        if r.get("_http_error") or "enc" not in r:
            return json.dumps({"ok": False, "stage": "result", "error": "bad envelope"})
        try:
            inner = secure_unpack(LINK_KEY, str(r["enc"]))
        except Exception:
            return json.dumps({"ok": False, "stage": "decrypt", "error": "wrong link key?"})
        inner.pop("ts", None)
        return json.dumps({"ok": True, "id": rid, "result": inner})
    return json.dumps({"ok": False, "stage": "timeout", "id": rid})


def _ensure_session() -> str | None:
    try:
        r = L.ssh_join(COMPUTER_ID, PI_IDENT,
                       secure_pack(LINK_KEY, {"hello": "mcp", "ts": int(time.time())}))
    except Exception as e:
        return f"join failed: {e}"
    if r.get("_http_error"):
        return f"join http {r.get('_http_error')}"
    return None


def _run_op(op: dict, wait_s: int) -> str:
    err = _ensure_session()
    if err:
        return json.dumps({"ok": False, "error": err})
    rid = f"mcp{int(time.time() * 1000)}"
    r = _send(op, rid)
    if not r.get("ok"):
        return json.dumps({"ok": False, "stage": "request", "error": r.get("error")})
    return _collect(rid, wait_s)


def _t_ssh_exec(a: dict) -> str:
    return _run_op({"kind": "exec", "cmd": str(a.get("cmd", ""))[:4000]},
                   int(a.get("wait_s", 120) or 120))


def _t_ssh_read(a: dict) -> str:
    return _run_op({"kind": "read", "path": str(a.get("path", ""))[:1024]},
                   int(a.get("wait_s", 120) or 120))


def _t_ssh_write(a: dict) -> str:
    return _run_op({"kind": "write", "path": str(a.get("path", ""))[:1024],
                    "data_b64": str(a.get("data_b64", ""))},
                   int(a.get("wait_s", 120) or 120))


def _t_ssh_install(a: dict) -> str:
    return _run_op({"kind": "install", "pkg": str(a.get("pkg", ""))[:256]},
                   int(a.get("wait_s", 300) or 300))


def _t_ssh_write_stream(a: dict) -> str:
    err = _ensure_session()
    if err:
        return json.dumps({"ok": False, "error": err})
    try:
        raw = base64.b64decode(str(a.get("data_b64", "")))
    except Exception:
        return json.dumps({"ok": False, "error": "bad data_b64"})
    n = 500_000
    parts = [secure_pack(LINK_KEY, {"chunk": base64.b64encode(raw[i:i + n]).decode()})
             for i in range(0, len(raw), n)] or [secure_pack(LINK_KEY, {"chunk": ""})]
    rid = f"ms{int(time.time() * 1000)}"
    r = _send({"kind": "write-parts", "path": str(a.get("path", ""))[:1024],
               "parts": parts}, rid)
    if not r.get("ok"):
        return json.dumps({"ok": False, "stage": "send", "error": "enqueue failed"})
    return _collect(rid, int(a.get("wait_s", 300) or 300))


def _t_ssh_reconnect(a: dict) -> str:
    err = _ensure_session()
    return json.dumps({"ok": err is None, "error": err})


def _t_ssh_status(a: dict) -> str:
    try:
        st = L.ssh_status(PI_IDENT)
    except Exception as e:
        return json.dumps({"ok": False, "error": f"{e}"})
    return json.dumps({"ok": True, "presence": st})


_HANDLERS = {
    "ssh_exec": _t_ssh_exec,
    "ssh_read": _t_ssh_read,
    "ssh_write": _t_ssh_write,
    "ssh_write_stream": _t_ssh_write_stream,
    "ssh_install": _t_ssh_install,
    "ssh_reconnect": _t_ssh_reconnect,
    "ssh_status": _t_ssh_status,
}

_WAIT = {"type": "integer", "description": "Seconds to wait", "default": 120}
TOOLS = [
    {"name": "ssh_exec", "description": "Run a root shell command on the Pi.",
     "inputSchema": {"type": "object", "properties": {
         "cmd": {"type": "string", "description": "Shell command"}, "wait_s": _WAIT},
         "required": ["cmd"]}},
    {"name": "ssh_read", "description": "Read a Pi file (base64 in result).",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string"}, "wait_s": _WAIT}, "required": ["path"]}},
    {"name": "ssh_write", "description": "Write a Pi file.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string"}, "data_b64": {"type": "string"}, "wait_s": _WAIT},
         "required": ["path", "data_b64"]}},
    {"name": "ssh_write_stream", "description": "Stream a BIG file to the Pi in encrypted chunks.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string"}, "data_b64": {"type": "string"},
         "wait_s": {"type": "integer", "default": 300}}, "required": ["path", "data_b64"]}},
    {"name": "ssh_install", "description": "apt-install a package on the Pi.",
     "inputSchema": {"type": "object", "properties": {
         "pkg": {"type": "string"},
         "wait_s": {"type": "integer", "default": 300}}, "required": ["pkg"]}},
    {"name": "ssh_reconnect", "description": "Force SSH session rejoin.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "ssh_status", "description": "Pi presence/heartbeat status.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _reply(mid, result=None, error=None) -> None:
    msg: dict = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result if result is not None else {}
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def serve(link_key: str, pi_ident: str = "", computer_id: str = "") -> None:
    global LINK_KEY, PI_IDENT, COMPUTER_ID
    LINK_KEY, PI_IDENT, COMPUTER_ID = link_key, pi_ident, computer_id
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    inp = sys.stdin.buffer
    while True:
        try:
            line = inp.readline()
        except Exception:
            return
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode("utf-8"))
        except Exception:
            continue
        method, mid, params = msg.get("method", ""), msg.get("id"), msg.get("params") or {}
        try:
            if method == "initialize":
                _reply(mid, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                             "serverInfo": {"name": "pnasyscnct-ssh", "version": __version__}})
            elif method in ("notifications/initialized", "notifications/cancelled"):
                pass
            elif method == "ping":
                _reply(mid, {})
            elif method == "tools/list":
                _reply(mid, {"tools": TOOLS})
            elif method == "tools/call":
                handler = _HANDLERS.get(params.get("name") or "")
                if handler is None:
                    _reply(mid, error={"code": -32602,
                                       "message": f"unknown tool: {params.get('name')}"})
                    continue
                try:
                    text = handler(params.get("arguments") or {})
                except Exception:
                    logger.exception("tool failed")
                    text = json.dumps({"ok": False, "error": "tool failed"})
                _reply(mid, {"content": [{"type": "text", "text": text}]})
            elif mid is None:
                pass
            else:
                _reply(mid, error={"code": -32601, "message": f"unknown method: {method}"})
        except Exception:
            logger.exception("dispatch failed")
            if mid is not None:
                try:
                    _reply(mid, error={"code": -32603, "message": "internal error"})
                except Exception:
                    return


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="pnasyscnct MCP (stdio).")
    ap.add_argument("--enckey", default="", help="link encryption key")
    ap.add_argument("--sshdev", default="", help="device name from pairing")
    ap.add_argument("--pi-ident", default="")
    ap.add_argument("--computer-id", default="")
    args = ap.parse_args(argv)
    if not args.enckey:
        print("--enckey (the link encryption key) is required.", file=sys.stderr)
        raise SystemExit(2)
    devs = L.pc_devices()
    if args.sshdev:
        if args.sshdev not in devs:
            print(f"Unknown device '{args.sshdev}'.", file=sys.stderr)
            raise SystemExit(2)
        meta = devs[args.sshdev]
        args.pi_ident = args.pi_ident or meta["pi_ident"]
        args.computer_id = args.computer_id or meta["computer_id"]
    if not args.pi_ident:
        print("Need --sshdev (or --pi-ident).", file=sys.stderr)
        raise SystemExit(2)
    serve(link_key=args.enckey, pi_ident=args.pi_ident, computer_id=args.computer_id)


if __name__ == "__main__":
    main()
