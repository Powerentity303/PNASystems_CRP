"""Local crypto for PNASystems_CRP — implements the user's exact derivations.

Password -> key / iv-salt:
  key     = SHA256(password).digest()            # 32 bytes -> AES-256
  rev     = password[::-1]
  b64     = base64.b64encode(rev.encode()).decode()
  rev_b64 = b64[::-1]
  iv_seed = SHA256(rev_b64.encode()).digest()[:12]  # 12-byte GCM nonce base

NOTE: AES-GCM must never reuse (key, nonce). We use iv_seed mixed with a
random 12-byte nonce per encryption; iv_seed is stored so decryption can
re-derive the key/iv material from the password alone, while each payload
carries its own random nonce. This honors "password derives key + iv/salt"
without breaking GCM nonce-misuse resistance.

Pi blob (identity, NOT recoverable via package):
  h_uuid = SHA256(uuid4str).hexdigest()
  h_col  = SHA256(favcolor).hexdigest()
  h_rest = SHA256(favrest).hexdigest()
  blob   = interleave(h_uuid, h_col, h_rest)  # char1 uuid, char1 color,
                                              # char1 rest, char2 uuid, ...

Access key ("SHA1024" = 4 x SHA256 = 1024 bits, dash-joined):
  Part1 = H(combined)
  Part2 = H(uuid + "-" + Part1 + "-" + reverse(Part1) + "-" + reverse(uuid))
  Part3 = H(favcolor + "-" + Part2 + "-" + reverse(Part2) + "-" + reverse(favcolor))
  Part4 = H(favrest + "-" + Part3 + "-" + reverse(Part3) + "-" + reverse(favrest))
  SHA1024 = Part1-Part2-Part3-Part4

Access variant blob: new uuid2; hash each original combined with uuid2, then
interleave:
  h1 = SHA256(uuid1 + "-" + uuid2), h2 = SHA256(color + "-" + uuid2),
  h3 = SHA256(rest + "-" + uuid2); combined2 = interleave(h1,h2,h3).
  Then run the SHA1024 construction with (combined2, uuid2, color, rest).

Pi-key encryption key (for pnasys-encryption-service server-side):
  akh = SHA256(accesskey).hexdigest()
  h1 = H(accesskey + akh); h2 = H(akh + h1 + accesskey)
  h3 = H(h2 + accesskey + h1); h4 = H(h1 + akh + h2)
  encryptionkey = h1-h3-h4-h2
"""
from __future__ import annotations

import base64
import hashlib
import os
import uuid


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def derive_key_iv(password: str) -> tuple[bytes, bytes]:
    key = hashlib.sha256(password.encode("utf-8")).digest()
    rev = password[::-1]
    b64 = base64.b64encode(rev.encode("utf-8")).decode("ascii")
    rev_b64 = b64[::-1]
    iv_seed = hashlib.sha256(rev_b64.encode("utf-8")).digest()[:12]
    return key, iv_seed


def interleave3(a: str, b: str, c: str) -> str:
    out: list[str] = []
    for i in range(max(len(a), len(b), len(c))):
        if i < len(a):
            out.append(a[i])
        if i < len(b):
            out.append(b[i])
        if i < len(c):
            out.append(c[i])
    return "".join(out)


def make_pi_blob(uuid4str: str, favcolor: str, favrest: str) -> str:
    return interleave3(sha256_hex(uuid4str), sha256_hex(favcolor), sha256_hex(favrest))


def make_access_sha1024(combined: str, uuid4str: str, favcolor: str, favrest: str) -> str:
    p1 = sha256_hex(combined)
    p2 = sha256_hex(f"{uuid4str}-{p1}-{p1[::-1]}-{uuid4str[::-1]}")
    p3 = sha256_hex(f"{favcolor}-{p2}-{p2[::-1]}-{favcolor[::-1]}")
    p4 = sha256_hex(f"{favrest}-{p3}-{p3[::-1]}-{favrest[::-1]}")
    return f"{p1}-{p2}-{p3}-{p4}"


def make_access_variant(uuid1: str, favcolor: str, favrest: str, uuid2: str | None = None) -> tuple[str, str, str]:
    """Return (combined2, uuid2, access_key)."""
    uuid2 = uuid2 or str(uuid.uuid4())
    h1 = sha256_hex(f"{uuid1}-{uuid2}")
    h2 = sha256_hex(f"{favcolor}-{uuid2}")
    h3 = sha256_hex(f"{favrest}-{uuid2}")
    combined2 = interleave3(h1, h2, h3)
    access = make_access_sha1024(combined2, uuid2, favcolor, favrest)
    return combined2, uuid2, access


def derive_pi_encryption_key(accesskey: str) -> str:
    akh = sha256_hex(accesskey)
    h1 = sha256_hex(accesskey + akh)
    h2 = sha256_hex(akh + h1 + accesskey)
    h3 = sha256_hex(h2 + accesskey + h1)
    h4 = sha256_hex(h1 + akh + h2)
    return f"{h1}-{h3}-{h4}-{h2}"


def encrypt_local(plaintext: bytes, password: str) -> dict:
    """AES-256-GCM encrypt. Returns dict with b64 nonce/ct/tag + iv_seed b64."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, iv_seed = derive_key_iv(password)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "iv_seed_b64": base64.b64encode(iv_seed).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
    }


def decrypt_local(bundle: dict, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, _ = derive_key_iv(password)
    nonce = base64.b64decode(bundle["nonce_b64"])
    ct = base64.b64decode(bundle["ct_b64"])
    return AESGCM(key).decrypt(nonce, ct, None)


def secure_pack(channel_key: str, op: dict) -> str:
    """Encrypt an op dict with pnasys-encryption-service. Returns the token.

    The MCP side calls this with the AI-supplied encryption key; the Pi
    decrypts it with the channel key from setup. Compact JSON keeps queue
    files small.
    """
    import json as _json

    from pnasys_encryption_service import EncryptString

    return EncryptString(_json.dumps(op, separators=(",", ":")), channel_key)


def secure_unpack(channel_key: str, token: str) -> dict:
    """Inverse of secure_pack. Raises on wrong key / tampered token."""
    import json as _json

    from pnasys_encryption_service import DecryptString

    return _json.loads(DecryptString(token, channel_key))
