"""GitHub Contents-API backend for the key DB and queue repos.

- Serial requests only (GitHub returns 409 on parallel writes to one repo).
- Up to 15 retries with growing cooldowns; chunk size shrinks per attempt.
- Large payloads: base64 split into <path>.partNNN + <path>.meta.json.
- Queue filenames carry a -<rand7> suffix so concurrent writers never
  collide on the same path.
- Token stays in-memory; every raised error is redacted (no Authorization
  header, no raw body with secrets).
"""
from __future__ import annotations

import base64
import json
import random
import re
import string
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
MAX_RETRIES = 15
BASE_CHUNK = 900_000  # base64 chars per part file


def _redact(s: object) -> str:
    t = s if isinstance(s, str) else str(s)
    t = re.sub(r"ghp_[A-Za-z0-9_\-]+", "[REDACTED]", t)
    t = re.sub(r"github_pat_[A-Za-z0-9_\-]+", "[REDACTED]", t)
    t = re.sub(r"gho_[A-Za-z0-9_\-]+", "[REDACTED]", t)
    t = re.sub(r"vcp_[A-Za-z0-9_\-]+", "[REDACTED]", t)
    t = re.sub(r"Bearer\s+\S+", "Bearer [REDACTED]", t)
    return t


def _auth(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",  # in-memory only, never logged
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "pnasys-crp-api",
    }


def _call(url: str, token: str, method: str = "GET", body: dict | None = None,
          timeout: int = 30, retries: int = 6) -> tuple[int, str]:
    """GitHub request with retries on network errors, 5xx and 429.

    4xx (except 429) is returned immediately — 404 means 'absent' in the
    get/list/delete flows and must not be retried into existence.
    """
    data = json.dumps(body).encode() if body is not None else None
    last: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method=method, headers=_auth(token))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", "replace")
            except Exception:
                detail = ""
            if e.code == 429 or 500 <= e.code < 600:
                last = RuntimeError(f"HTTP {e.code}")
                time.sleep(min(20.0, 1.0 * (attempt + 1)))
                continue
            return e.code, detail
        except Exception as e:
            last = e
            time.sleep(min(20.0, 1.0 * (attempt + 1)))
    raise RuntimeError(f"github request failed after {retries}: {_redact(last)[:200]}")


def _get_sha(owner_repo: str, path: str, token: str, branch: str) -> str | None:
    st, body = _call(f"{API}/repos/{owner_repo}/contents/{path}?ref={branch}", token)
    if st == 200:
        try:
            return json.loads(body).get("sha")
        except Exception:
            return None
    return None


def _put_text(owner_repo: str, path: str, text: str, message: str,
              token: str, branch: str) -> None:
    sha = _get_sha(owner_repo, path, token, branch)
    content = base64.b64encode(text.encode("utf-8")).decode("ascii")
    body: dict = {"message": message, "content": content, "branch": branch}
    if sha:
        body["sha"] = sha
    st, resp = _call(f"{API}/repos/{owner_repo}/contents/{path}", token,
                     method="PUT", body=body)
    if st not in (200, 201):
        raise RuntimeError(f"PUT {path}: HTTP {st} :: {_redact(resp)[:300]}")


def put_file(owner_repo: str, path: str, raw: bytes, message: str, token: str,
             branch: str = "main", chunk_size: int = BASE_CHUNK) -> None:
    """Store raw bytes (base64-chunked when large) with 15 shrinking retries."""
    b64 = base64.b64encode(raw).decode("ascii")
    size = chunk_size
    last: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            parts = [b64[i:i + size] for i in range(0, len(b64), size)] or [""]
            if len(parts) == 1:
                _put_text(owner_repo, path, parts[0], message, token, branch)
            else:
                meta = json.dumps({"parts": len(parts), "encoding": "base64"})
                _put_text(owner_repo, path + ".meta.json", meta, message, token, branch)
                for i, p in enumerate(parts):
                    _put_text(owner_repo, f"{path}.part{i:03d}", p, message, token, branch)
            return
        except Exception as e:
            last = e
            size = max(100_000, size * 3 // 4)
            time.sleep(min(30.0, 1.5 * (attempt + 1)))
    raise RuntimeError(f"github put failed after {MAX_RETRIES}: {_redact(last)[:300]}")


def get_file(owner_repo: str, path: str, token: str, branch: str = "main") -> bytes | None:
    """Fetch a (possibly chunked) file. Returns None when absent."""
    st, body = _call(f"{API}/repos/{owner_repo}/contents/{path}.meta.json?ref={branch}", token)
    if st == 200:
        try:
            meta = json.loads(base64.b64decode(json.loads(body)["content"]).decode())
            n = int(meta.get("parts", 0))
        except Exception:
            return None
        chunks: list[str] = []
        for i in range(n):
            pst, pbody = _call(
                f"{API}/repos/{owner_repo}/contents/{path}.part{i:03d}?ref={branch}", token)
            if pst != 200:
                return None
            try:
                chunks.append(base64.b64decode(json.loads(pbody)["content"]).decode("ascii"))
            except Exception:
                return None
        try:
            return base64.b64decode("".join(chunks))
        except Exception:
            return None
    st, body = _call(f"{API}/repos/{owner_repo}/contents/{path}?ref={branch}", token)
    if st != 200:
        return None
    try:
        payload = json.loads(body)
        if isinstance(payload, list):
            return None
        return base64.b64decode(payload["content"])
    except Exception:
        return None


def delete_file(owner_repo: str, path: str, message: str, token: str,
                branch: str = "main") -> bool:
    """Delete file (and any chunk parts). True if something was deleted."""
    deleted = False
    # Chunked?
    st, body = _call(f"{API}/repos/{owner_repo}/contents/{path}.meta.json?ref={branch}", token)
    if st == 200:
        try:
            meta = json.loads(base64.b64decode(json.loads(body)["content"]).decode())
            n = int(meta.get("parts", 0))
        except Exception:
            n = 0
        for i in range(n):
            _delete_one(owner_repo, f"{path}.part{i:03d}", message, token, branch)
        _delete_one(owner_repo, path + ".meta.json", message, token, branch)
        deleted = True
    return _delete_one(owner_repo, path, message, token, branch) or deleted


def _delete_one(owner_repo: str, path: str, message: str, token: str, branch: str) -> bool:
    sha = _get_sha(owner_repo, path, token, branch)
    if not sha:
        return False
    st, resp = _call(f"{API}/repos/{owner_repo}/contents/{path}", token, method="DELETE",
                     body={"message": message, "sha": sha, "branch": branch})
    if st == 200:
        return True
    raise RuntimeError(f"DELETE {path}: HTTP {st} :: {_redact(resp)[:200]}")


def list_dir(owner_repo: str, path: str, token: str, branch: str = "main") -> list[dict]:
    st, body = _call(f"{API}/repos/{owner_repo}/contents/{path}?ref={branch}", token)
    if st == 404:
        return []
    if st != 200:
        raise RuntimeError(f"LIST {path}: HTTP {st} :: {_redact(body)[:200]}")
    try:
        data = json.loads(body)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def rand7() -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(7))
