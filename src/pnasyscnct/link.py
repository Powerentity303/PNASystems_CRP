"""Pairing + link transport over the Vercel API (all payloads opaque).

Computer vault: pnasys-ses (TPM on Win11) slot "cnct_link", EncryptionKey =
local password. Plaintext state.json holds non-secret ids.
Pi vault: AES-GCM files under ~/.pnasys_crp/.vault (no TPM on Pi).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

HOME = Path.home()
SAFE = HOME / ".pnasys_crp"
VAULT = SAFE / ".vault"
STATE = SAFE / "state.json"
LINK_AES = VAULT / "link.enc.json"  # Pi side: AES(local pw) {computer_id, pi_ident, link_key}


def base() -> str:
    try:
        return json.loads(STATE.read_text()).get("vercel_base", "") or \
            os.environ.get("PNASYS_VERCEL_BASE", "https://pnasys-crp-api.vercel.app")
    except Exception:
        return os.environ.get("PNASYS_VERCEL_BASE", "https://pnasys-crp-api.vercel.app")


def api(method: str, path: str, body: dict | None = None, timeout: int = 65) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base().rstrip("/") + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return json.loads(raw)
            except Exception:
                return {"_text": raw[:500]}
    except urllib.error.HTTPError as e:
        try:
            return {"_http_error": e.code, **json.loads(e.read().decode()[:300])}
        except Exception:
            return {"_http_error": e.code}


def ident_of(access_key: str) -> str:
    return hashlib.sha256(access_key.encode()).hexdigest()


def fingerprint(link_key: str) -> str:
    """Public fingerprint of a link key (safe to store server-side)."""
    return hashlib.sha256(("fp|" + link_key).encode()).hexdigest()


def sas(pair_key: str, code: str) -> str:
    """CHECK-1: short auth string both humans compare (anti-MITM)."""
    h = hashlib.sha256((pair_key + "|" + code).encode()).hexdigest()[:12]
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}".upper()


def code_echo(code: str) -> str:
    """CHECK-2: proves the other side decrypted our message."""
    return hashlib.sha256(("echo|" + code).encode()).hexdigest()


def session_ack(nonce: str, link_key: str) -> str:
    """CHECK-3: per-session proof of key possession (no key revealed)."""
    return hashlib.sha256((nonce + "|" + link_key).encode()).hexdigest()


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {}


def save_state(patch: dict) -> None:
    SAFE.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = load_state()
    s.update(patch)
    STATE.write_text(json.dumps(s, indent=2))
    try:
        os.chmod(STATE, 0o600)
    except Exception:
        pass


# --- computer vault (pnasys-ses, TPM). One slot per device name. ---

def _link_slot(name: str) -> str:
    name = (name or "default").strip() or "default"
    return f"cnct_link:{name}"


def pc_save_link(computer_id: str, pi_ident: str, link_key: str, local_pw: str,
                 name: str = "default") -> None:
    from pnasys_ses import SecureEncryptionService as SES

    name = (name or "default").strip() or "default"
    SES.CreateEncryptedFile(json.dumps({"computer_id": computer_id, "pi_ident": pi_ident,
                                        "link_key": link_key}), _link_slot(name), local_pw)
    st = load_state()
    devs = st.get("devices", {})
    devs[name] = {"computer_id": computer_id, "pi_ident": pi_ident}
    st["devices"] = devs
    save_state(st)


def pc_load_link(local_pw: str, name: str = "default") -> dict:
    from pnasys_ses import SecureEncryptionService as SES

    return json.loads(SES.DecryptEncryptedFile(_link_slot(name), local_pw))


def pc_devices() -> dict:
    return load_state().get("devices", {})


# --- pi vault (AES-GCM, local pw) ---

def pi_save_link(computer_id: str, pi_ident: str, link_key: str, local_pw: str,
                 name: str = "default") -> None:
    from pnasyscnct.common import encrypt_local

    VAULT.mkdir(mode=0o700, parents=True, exist_ok=True)
    LINK_AES.write_text(json.dumps(encrypt_local(
        json.dumps({"computer_id": computer_id, "pi_ident": pi_ident,
                    "link_key": link_key, "name": name}).encode(), local_pw)))
    try:
        os.chmod(LINK_AES, 0o600)
    except Exception:
        pass
    st = load_state()
    devs = st.get("devices", {})
    devs[name] = {"computer_id": computer_id, "pi_ident": pi_ident}
    st["devices"] = devs
    save_state(st)


def pi_load_link(local_pw: str) -> dict:
    from pnasyscnct.common import decrypt_local

    return json.loads(decrypt_local(json.loads(LINK_AES.read_text()), local_pw).decode())


# --- pairing / presence calls (opaque blobs; Vercel never decrypts) ---

def link_request(computer_id: str, blob: str) -> dict:
    return api("POST", "/api/link/request", {"computer_id": computer_id, "blob": blob})


def link_poll(computer_id: str) -> dict:
    return api("GET", f"/api/link/poll?computer_id={computer_id}", timeout=65)


def link_answer(computer_id: str, blob: str, for_pi: str = "") -> dict:
    body = {"computer_id": computer_id, "blob": blob}
    if for_pi:
        body["for_pi"] = for_pi
    return api("POST", "/api/link/answer", body)


def link_wait(computer_id: str, pi_ident: str) -> dict:
    return api("GET", f"/api/link/wait?computer_id={computer_id}&pi_ident={pi_ident}", timeout=65)


def ssh_hello(pi_ident: str, blob: str) -> dict:
    return api("POST", "/api/ssh/hello", {"pi_ident": pi_ident, "blob": blob})


def ssh_status(pi_ident: str) -> dict:
    return api("GET", f"/api/ssh/status?pi_ident={pi_ident}", timeout=25)


def ssh_join(computer_id: str, pi_ident: str, blob: str, fp: str = "") -> dict:
    body: dict = {"computer_id": computer_id, "pi_ident": pi_ident, "blob": blob}
    if fp:
        body["fp"] = fp
    return api("POST", "/api/ssh/join", body)


def ssh_wait_join(pi_ident: str) -> dict:
    return api("GET", f"/api/ssh/wait?pi_ident={pi_ident}", timeout=65)


def ssh_ack_post(pi_ident: str, ack: str) -> dict:
    return api("POST", "/api/ssh/ack", {"pi_ident": pi_ident, "ack": ack})


def ssh_ack_get(pi_ident: str) -> dict:
    return api("GET", f"/api/ssh/ack?pi_ident={pi_ident}", timeout=25)


def check_deleted(pi_ident: str) -> dict:
    return api("GET", f"/api/check-deleted?pi_ident={pi_ident}", timeout=25)


def purge(pi_ident: str, access_key: str = "", fp: str = "") -> dict:
    body: dict = {"pi_ident": pi_ident}
    if access_key:
        body["access_key"] = access_key
    if fp:
        body["fp"] = fp
    return api("POST", "/api/purge", body)


def mark_deleted(pi_ident: str, access_key: str = "", fp: str = "") -> dict:
    body: dict = {"pi_ident": pi_ident}
    if access_key:
        body["access_key"] = access_key
    if fp:
        body["fp"] = fp
    return api("POST", "/api/mark-deleted", body)


def reset_pin(pi_ident: str, what: str = "all", access_key: str = "", fp: str = "") -> dict:
    body: dict = {"pi_ident": pi_ident, "what": what}
    if access_key:
        body["access_key"] = access_key
    if fp:
        body["fp"] = fp
    return api("POST", "/api/link/reset", body)


def enqueue(access_key: str, kind: str, fields: dict, rid: str | None = None) -> dict:
    body = {"access_key": access_key, "kind": kind}
    body.update(fields)
    if rid:
        body["id"] = rid
    return api("POST", "/api/request", body)


def fetch_result(ident: str, rid: str) -> dict:
    return api("GET", f"/api/result?ident={ident}&id={rid}", timeout=65)


def wait_result(ident: str, rid: str, wait_s: int = 120) -> dict:
    deadline = time.time() + max(5, min(wait_s, 300))
    while time.time() < deadline:
        r = fetch_result(ident, rid)
        if not r.get("pending"):
            return r
        time.sleep(5)
    return {"pending": True, "timeout": True}


def check_health() -> dict:
    return api("GET", "/api/health", timeout=20)
