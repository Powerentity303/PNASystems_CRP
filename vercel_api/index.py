"""PNASystems CRP main API (Flask, Vercel Python runtime).

Vercel detects this via `Flask` in requirements + this `index.py`
entrypoint at the deployment root (no git link; deployed by file upload).

Env (server-side only; GITHUB_TOKEN stored as Sensitive):
  GITHUB_TOKEN, KEY_REPO (private #1, key DB), QUEUE_REPO (private #2),
  KEY_REPO_BRANCH=main, QUEUE_REPO_BRANCH=main

Routes:
  GET  /api/health
  POST /api/register  {pi_blob, access_key}
  POST /api/request   {access_key, kind, cmd|path|data_b64|pkg|blob, id?}
                        kind=secure carries an opaque pnasys-encrypted op blob
  GET  /api/poll?ident=            -> oldest queued request (claimed+deleted)
  POST /api/respond   {ident, id, ...result...}
  POST /api/stream    {ident, id, seq, data_b64, last}
  GET  /api/result?ident=&id=      -> response or stream-assembly
  POST /api/revoke    {access_key}

The raw access key never appears in filenames or logs; only its SHA256.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time

from flask import Flask, Response, jsonify, request

from lib import github_store as gs
from lib.crypto_server import decrypt_pi_blob, encrypt_pi_blob, ident_for

app = Flask(__name__)

KINDS = ("exec", "read", "write", "install", "secure")


def _redact(s: object) -> str:
    t = s if isinstance(s, str) else str(s)
    t = re.sub(r"ghp_[A-Za-z0-9_\-]+", "[REDACTED]", t)
    t = re.sub(r"github_pat_[A-Za-z0-9_\-]+", "[REDACTED]", t)
    t = re.sub(r"vcp_[A-Za-z0-9_\-]+", "[REDACTED]", t)
    return t


def _cfg() -> dict:
    tok = os.environ.get("GITHUB_TOKEN", "")
    if not tok:
        raise RuntimeError("GITHUB_TOKEN not configured")
    return {
        "token": tok,
        "keys": os.environ.get("KEY_REPO", ""),
        "queue": os.environ.get("QUEUE_REPO", ""),
        "kb": os.environ.get("KEY_REPO_BRANCH", "main"),
        "qb": os.environ.get("QUEUE_REPO_BRANCH", "main"),
    }


def _key_path(ident: str) -> str:
    return f"keys/{ident}.json"


def _check_registered(cfg: dict, access_key: str) -> str:
    """Return ident if access_key has a key file, else raise."""
    ident = ident_for(access_key)
    raw = gs.get_file(cfg["keys"], _key_path(ident), cfg["token"], cfg["kb"])
    if raw is None:
        raise LookupError("unknown access key")
    return ident


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "time": int(time.time())})


@app.post("/api/register")
def register():
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        pi_blob = str(data.get("pi_blob", ""))
        access_key = str(data.get("access_key", ""))
        if len(pi_blob) != 64 * 3 or len(access_key.split("-")) != 4:
            return jsonify({"error": "bad key shapes"}), 400
        ident = ident_for(access_key)
        token = encrypt_pi_blob(pi_blob, access_key)
        payload = json.dumps({"enc_pi_blob": token, "created": int(time.time())}).encode()
        gs.put_file(cfg["keys"], _key_path(ident), payload, "register pi key", cfg["token"], cfg["kb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/request")
def make_request():
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        access_key = str(data.get("access_key", ""))
        kind = str(data.get("kind", ""))
        if kind not in KINDS:
            return jsonify({"error": "bad kind"}), 400
        ident = _check_ident_or_key(cfg, access_key)
        rid = str(data.get("id") or f"r{int(time.time() * 1000)}")
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", rid):
            return jsonify({"error": "bad id"}), 400
        job: dict = {"id": rid, "kind": kind, "ts": int(time.time())}
        if kind == "exec":
            job["cmd"] = str(data.get("cmd", ""))[:4000]
        elif kind == "read":
            job["path"] = str(data.get("path", ""))[:1024]
        elif kind == "write":
            job["path"] = str(data.get("path", ""))[:1024]
            job["data_b64"] = str(data.get("data_b64", ""))
        elif kind == "install":
            job["pkg"] = str(data.get("pkg", ""))[:256]
        elif kind == "secure":
            # Opaque pnasys-encrypted op; server never inspects it. The Pi
            # decrypts it with the setup channel key.
            job["blob"] = str(data.get("blob", ""))
        fname = f"queue/{ident}-{int(time.time() * 1000)}-{gs.rand7()}.json"
        gs.put_file(cfg["queue"], fname, json.dumps(job).encode(),
                    f"enqueue {rid}", cfg["token"], cfg["qb"])
        return jsonify({"ok": True, "id": rid})
    except LookupError:
        return jsonify({"error": "unknown access key"}), 403
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.get("/api/poll")
def poll():
    """Pi long-polls. Returns oldest job for ident, claimed (deleted)."""
    try:
        cfg = _cfg()
        ident = str(request.args.get("ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", ident):
            return jsonify({"error": "bad ident"}), 400
        try:
            _ = _check_registered_by_ident(cfg, ident)
        except LookupError:
            return jsonify({"error": "unknown ident"}), 403
        entries: list = []
        name = ""
        for _ in range(5):
            entries = gs.list_dir(cfg["queue"], "queue", cfg["token"], cfg["qb"])
            cands = [e["name"] for e in entries
                     if e.get("type") == "file" and e["name"].startswith(ident + "-")
                     and e["name"].endswith(".json")]
            if cands:
                cands.sort()  # ts-prefixed names sort oldest-first
                name = cands[0]
                break
            time.sleep(4)
        if not name:
            return jsonify({"empty": True})
        raw = None
        for _ in range(4):
            raw = gs.get_file(cfg["queue"], f"queue/{name}", cfg["token"], cfg["qb"])
            if raw is not None:
                break
            time.sleep(3)
        if raw is None:
            return jsonify({"empty": True})
        try:
            job = json.loads(raw.decode())
        except Exception:
            # Corrupt payload: drop it so the queue never wedges on one file.
            gs.delete_file(cfg["queue"], f"queue/{name}", f"drop {name}", cfg["token"], cfg["qb"])
            return jsonify({"empty": True})
        gs.delete_file(cfg["queue"], f"queue/{name}", f"claim {name}", cfg["token"], cfg["qb"])
        return jsonify(job)
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


def _check_registered_by_ident(cfg: dict, ident: str) -> None:
    raw = gs.get_file(cfg["keys"], _key_path(ident), cfg["token"], cfg["kb"])
    if raw is None:
        raise LookupError("unknown ident")


@app.post("/api/respond")
def respond():
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        ident = str(data.get("ident", ""))
        rid = str(data.get("id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", ident) or not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", rid):
            return jsonify({"error": "bad ident/id"}), 400
        _check_registered_by_ident(cfg, ident)
        body = {k: v for k, v in data.items() if k not in ("ident",)}
        body["ts"] = int(time.time())
        gs.put_file(cfg["queue"], f"resp/{ident}-{rid}.json", json.dumps(body).encode(),
                    f"respond {rid}", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except LookupError:
        return jsonify({"error": "unknown ident"}), 403
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/stream")
def stream_part():
    """Pi uploads one chunk. On last=true, parts assemble into resp file."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        ident = str(data.get("ident", ""))
        rid = str(data.get("id", ""))
        seq = int(data.get("seq", 0))
        last = bool(data.get("last", False))
        if not re.fullmatch(r"[0-9a-f]{64}", ident) or not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", rid):
            return jsonify({"error": "bad ident/id"}), 400
        _check_registered_by_ident(cfg, ident)
        gs.put_file(cfg["queue"], f"stream/{ident}-{rid}.part{seq:05d}",
                    str(data.get("data_b64", "")).encode(),
                    f"stream {rid}#{seq}", cfg["token"], cfg["qb"])
        if last:
            parts: list[str] = []
            for i in range(10000):
                raw = gs.get_file(cfg["queue"], f"stream/{ident}-{rid}.part{i:05d}",
                                  cfg["token"], cfg["qb"])
                if raw is None:
                    break
                parts.append(raw.decode("ascii"))
            body = {"id": rid, "stream": True, "data_b64": "".join(parts),
                    "ts": int(time.time())}
            gs.put_file(cfg["queue"], f"resp/{ident}-{rid}.json", json.dumps(body).encode(),
                        f"assemble {rid}", cfg["token"], cfg["qb"])
            for i in range(len(parts)):
                gs.delete_file(cfg["queue"], f"stream/{ident}-{rid}.part{i:05d}",
                               f"cleanup {rid}", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except LookupError:
        return jsonify({"error": "unknown ident"}), 403
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.get("/api/result")
def result():
    """Requester fetches a response. Streamed payloads download chunked."""
    try:
        cfg = _cfg()
        ident = str(request.args.get("ident", ""))
        rid = str(request.args.get("id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", ident) or not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", rid):
            return jsonify({"error": "bad ident/id"}), 400
        raw = gs.get_file(cfg["queue"], f"resp/{ident}-{rid}.json", cfg["token"], cfg["qb"])
        if raw is None:
            return jsonify({"pending": True})
        body = json.loads(raw.decode())
        if body.get("stream") and len(body.get("data_b64", "")) > 2_000_000:
            # Too big for one JSON body: HTTP-stream it back.
            b64 = body["data_b64"]
            gs.delete_file(cfg["queue"], f"resp/{ident}-{rid}.json",
                           f"collect {rid}", cfg["token"], cfg["qb"])

            def generate():
                for i in range(0, len(b64), 700_000):
                    yield b64[i:i + 700_000]

            return Response(generate(), mimetype="text/plain")
        gs.delete_file(cfg["queue"], f"resp/{ident}-{rid}.json",
                       f"collect {rid}", cfg["token"], cfg["qb"])
        return jsonify(body)
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/revoke")
def revoke():
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        access_key = str(data.get("access_key", ""))
        ident = ident_for(access_key)
        ok = gs.delete_file(cfg["keys"], _key_path(ident), "revoke pi key",
                            cfg["token"], cfg["kb"])
        # Best-effort: drop this ident's pending queue files too.
        try:
            for e in gs.list_dir(cfg["queue"], "queue", cfg["token"], cfg["qb"]):
                if e.get("type") == "file" and e["name"].startswith(ident + "-"):
                    gs.delete_file(cfg["queue"], "queue/" + e["name"],
                                   "revoke cleanup", cfg["token"], cfg["qb"])
        except Exception:
            pass
        return jsonify({"ok": True, "deleted_key": ok})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


def _check_ident_or_key(cfg: dict, access_key: str) -> str:
    """kind=secure accepts a registered access key OR 'ident:<hex>' of one."""
    if access_key.startswith("ident:"):
        ident = access_key[6:]
        if not re.fullmatch(r"[0-9a-f]{64}", ident):
            raise LookupError("bad ident")
        _check_registered_by_ident(cfg, ident)
        return ident
    return _check_registered(cfg, access_key)


@app.post("/api/link/request")
def link_request():
    """Pi drops an opaque pairing blob for a computer id."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        cid = str(data.get("computer_id", ""))
        blob = str(data.get("blob", ""))
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", cid) or not blob:
            return jsonify({"error": "bad computer_id/blob"}), 400
        gs.put_file(cfg["queue"], f"link_req/{cid}.json",
                    json.dumps({"blob": blob, "ts": int(time.time())}).encode(),
                    "pairing request", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.get("/api/link/poll")
def link_poll():
    """Computer long-polls for its pairing request (claimed)."""
    try:
        cfg = _cfg()
        cid = str(request.args.get("computer_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", cid):
            return jsonify({"error": "bad computer_id"}), 400
        for _ in range(10):
            raw = gs.get_file(cfg["queue"], f"link_req/{cid}.json", cfg["token"], cfg["qb"])
            if raw is not None:
                gs.delete_file(cfg["queue"], f"link_req/{cid}.json",
                               "pairing claimed", cfg["token"], cfg["qb"])
                return jsonify(json.loads(raw.decode()))
            time.sleep(4)
        return jsonify({"empty": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/link/answer")
def link_answer():
    """Computer drops the opaque answer for the Pi."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        cid = str(data.get("computer_id", ""))
        blob = str(data.get("blob", ""))
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", cid) or not blob:
            return jsonify({"error": "bad computer_id/blob"}), 400
        # Filename carries no Pi identity until decrypted device-side; the Pi
        # polls its own slot below. Store per-computer; Pi claims by exact key.
        pi_hint = str(data.get("for_pi", ""))
        name = f"link_ans/{cid}-{pi_hint}.json" if re.fullmatch(r"[0-9a-f]{64}", pi_hint) \
            else f"link_ans/{cid}.json"
        gs.put_file(cfg["queue"], name,
                    json.dumps({"blob": blob, "ts": int(time.time())}).encode(),
                    "pairing answer", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.get("/api/link/wait")
def link_wait():
    """Pi long-waits for the computer's answer, then claims it."""
    try:
        cfg = _cfg()
        cid = str(request.args.get("computer_id", ""))
        pi = str(request.args.get("pi_ident", ""))
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", cid) or not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad ids"}), 400
        for name in (f"link_ans/{cid}-{pi}.json", f"link_ans/{cid}.json"):
            for _ in range(6):
                raw = gs.get_file(cfg["queue"], name, cfg["token"], cfg["qb"])
                if raw is not None:
                    gs.delete_file(cfg["queue"], name, "answer claimed",
                                   cfg["token"], cfg["qb"])
                    return jsonify(json.loads(raw.decode()))
                time.sleep(4)
        return jsonify({"empty": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/ssh/hello")
def ssh_hello():
    """Pi heartbeat (opaque). Overwrites each time."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        pi = str(data.get("pi_ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad pi_ident"}), 400
        gs.put_file(cfg["queue"], f"ssh/{pi}.json",
                    json.dumps({"blob": str(data.get("blob", "")),
                                "ts": int(time.time())}).encode(),
                    "presence", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.get("/api/ssh/status")
def ssh_status():
    try:
        cfg = _cfg()
        pi = str(request.args.get("pi_ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad pi_ident"}), 400
        raw = gs.get_file(cfg["queue"], f"ssh/{pi}.json", cfg["token"], cfg["qb"])
        if raw is None:
            return jsonify({"live": False})
        try:
            ts = json.loads(raw.decode()).get("ts", 0)
        except Exception:
            ts = 0
        return jsonify({"live": int(time.time()) - int(ts) < 120})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/ssh/join")
def ssh_join():
    """Computer opens a session. Fingerprint pinned per Pi (anti-MITM).

    First join for a Pi pins fp; later joins with a different fp get 403.
    Re-pairing resets the pin via /api/link/reset (access-key authenticated).
    """
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        pi = str(data.get("pi_ident", ""))
        cid = str(data.get("computer_id", ""))
        fp = str(data.get("fp", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi) or not cid:
            return jsonify({"error": "bad ids"}), 400
        if fp:
            if not re.fullmatch(r"[0-9a-f]{64}", fp):
                return jsonify({"error": "bad fp"}), 400
            pin_raw = gs.get_file(cfg["queue"], f"link_fp/{pi}.json", cfg["token"], cfg["qb"])
            if pin_raw is not None:
                try:
                    pinned = json.loads(pin_raw.decode()).get("fp", "")
                except Exception:
                    pinned = ""
                if pinned and pinned != fp:
                    return jsonify({"error": "fingerprint mismatch",
                                    "hint": "Pi re-keyed elsewhere or MITM replay. "
                                            "Re-pair if you rotated keys."}), 403
            else:
                gs.put_file(cfg["queue"], f"link_fp/{pi}.json",
                            json.dumps({"fp": fp, "ts": int(time.time())}).encode(),
                            "pin fingerprint", cfg["token"], cfg["qb"])
        gs.put_file(cfg["queue"], f"ssh/{pi}-join.json",
                    json.dumps({"blob": str(data.get("blob", "")),
                                "ts": int(time.time())}).encode(),
                    "session join", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.get("/api/ssh/wait")
def ssh_wait():
    """Pi long-waits for a computer join, then claims it."""
    try:
        cfg = _cfg()
        pi = str(request.args.get("pi_ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad pi_ident"}), 400
        for _ in range(10):
            raw = gs.get_file(cfg["queue"], f"ssh/{pi}-join.json", cfg["token"], cfg["qb"])
            if raw is not None:
                gs.delete_file(cfg["queue"], f"ssh/{pi}-join.json",
                               "join claimed", cfg["token"], cfg["qb"])
                return jsonify(json.loads(raw.decode()))
            time.sleep(4)
        return jsonify({"empty": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/ssh/ack")
def ssh_ack():
    """Pi posts its session ack (unforgeable without the link key)."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        pi = str(data.get("pi_ident", ""))
        ack = str(data.get("ack", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi) or not re.fullmatch(r"[0-9a-f]{64}", ack):
            return jsonify({"error": "bad pi_ident/ack"}), 400
        gs.put_file(cfg["queue"], f"ssh/{pi}-ack.json",
                    json.dumps({"ack": ack, "ts": int(time.time())}).encode(),
                    "session ack", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.get("/api/ssh/ack")
def ssh_ack_get():
    try:
        cfg = _cfg()
        pi = str(request.args.get("pi_ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad pi_ident"}), 400
        raw = gs.get_file(cfg["queue"], f"ssh/{pi}-ack.json", cfg["token"], cfg["qb"])
        if raw is None:
            return jsonify({"pending": True})
        gs.delete_file(cfg["queue"], f"ssh/{pi}-ack.json", "ack collected",
                       cfg["token"], cfg["qb"])
        return jsonify(json.loads(raw.decode()))
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


def _auth_pi(cfg: dict, pi: str, access_key: str, fp: str, allow_unpinned_purge: bool = False) -> bool:
    """True if access_key owns this ident OR fp matches the pinned fp.

    allow_unpinned_purge (purge only): with no pin on record, any well-formed
    fp authorizes debris cleanup — heartbeats rewrite within a minute anyway,
    so there is nothing to gain by blocking it.
    """
    if access_key:
        try:
            _check_registered(cfg, access_key)
            return ident_for(access_key) == pi
        except LookupError:
            return False
    if fp and re.fullmatch(r"[0-9a-f]{64}", fp):
        raw = gs.get_file(cfg["queue"], f"link_fp/{pi}.json", cfg["token"], cfg["kb"])
        if raw is None:
            return allow_unpinned_purge
        try:
            return bool(raw) and json.loads(raw.decode()).get("fp", "") == fp
        except Exception:
            return False
    return False


@app.get("/api/check-deleted")
def check_deleted():
    try:
        cfg = _cfg()
        pi = str(request.args.get("pi_ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad pi_ident"}), 400
        raw = gs.get_file(cfg["queue"], f"deleted/{pi}.json", cfg["token"], cfg["qb"])
        if raw is None:
            return jsonify({"deleted": False})
        try:
            ts = json.loads(raw.decode()).get("ts", 0)
        except Exception:
            ts = 0
        return jsonify({"deleted": True, "ts": ts})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/mark-deleted")
def mark_deleted():
    """Pi tombstones itself (fp- or access-key authenticated)."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        pi = str(data.get("pi_ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad pi_ident"}), 400
        if not _auth_pi(cfg, pi, str(data.get("access_key", "")), str(data.get("fp", ""))):
            return jsonify({"error": "not authorized"}), 403
        gs.put_file(cfg["queue"], f"deleted/{pi}.json",
                    json.dumps({"ts": int(time.time()), "by": "pi"}).encode(),
                    "tombstone", cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/purge")
def purge():
    """Delete a Pi's queue/resp/stream/presence/link files (keeps keys, pin, tombstone)."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        pi = str(data.get("pi_ident", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", pi):
            return jsonify({"error": "bad pi_ident"}), 400
        if not _auth_pi(cfg, pi, str(data.get("access_key", "")), str(data.get("fp", "")),
                         allow_unpinned_purge=True):
            return jsonify({"error": "not authorized"}), 403
        n = 0
        for directory, prefix, suffix in (
                ("queue", pi + "-", ".json"), ("resp", pi + "-", ".json"),
                ("stream", pi + "-", ""), ("ssh", pi, ""), ("link_ans", "", "-" + pi + ".json")):
            try:
                entries = gs.list_dir(cfg["queue"], directory, cfg["token"], cfg["qb"])
            except Exception:
                continue
            for e in entries:
                if e.get("type") != "file":
                    continue
                name = e["name"]
                if name.startswith(prefix) and name.endswith(suffix):
                    try:
                        if gs.delete_file(cfg["queue"], f"{directory}/{name}",
                                          "purge", cfg["token"], cfg["qb"]):
                            n += 1
                    except Exception:
                        pass
        return jsonify({"ok": True, "deleted": n})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


@app.post("/api/link/reset")
def link_reset():
    """Clear pin and/or tombstone. what=pin keeps tombstone; what=all clears both."""
    try:
        cfg = _cfg()
        data = request.get_json(force=True)
        pi = str(data.get("pi_ident", ""))
        what = str(data.get("what", "all"))
        if not re.fullmatch(r"[0-9a-f]{64}", pi) or what not in ("pin", "all"):
            return jsonify({"error": "bad pi_ident/what"}), 400
        if not _auth_pi(cfg, pi, str(data.get("access_key", "")), str(data.get("fp", ""))):
            return jsonify({"error": "not authorized"}), 403
        gs.delete_file(cfg["queue"], f"link_fp/{pi}.json", "pin reset",
                       cfg["token"], cfg["qb"])
        if what == "all":
            gs.delete_file(cfg["queue"], f"deleted/{pi}.json", "tombstone cleared",
                           cfg["token"], cfg["qb"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": _redact(e)[:200]}), 500


# Local dev only; Vercel imports `app`.
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
