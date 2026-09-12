"""Shared crypto: AES-256-GCM at-rest, pnasys transport, keygen, identity math.

- AES key  = SHA256(password).digest()  (32B)
- AES iv   = SHA256(reverse(b64(reverse(password)))).digest()[:12]
- Transport (pnasys-encryption-service): session/link keys, exact ops.
- Session/link code generator: exact PNASystemsKeyGenerator.py logic.
- Pi identity: interleave blob + SHA1024 + uuid2 variant (unchanged spec).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import os
import secrets
import uuid


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def derive_key_iv(password: str) -> tuple[bytes, bytes]:
    key = hashlib.sha256(password.encode("utf-8")).digest()
    rev_b64 = base64.b64encode(password[::-1].encode("utf-8")).decode("ascii")[::-1]
    return key, hashlib.sha256(rev_b64.encode("utf-8")).digest()[:12]


def encrypt_local(plaintext: bytes, password: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, _ = derive_key_iv(password)
    nonce = os.urandom(12)
    return {"nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ct_b64": base64.b64encode(AESGCM(key).encrypt(nonce, plaintext, None)).decode("ascii")}


def decrypt_local(bundle: dict, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, _ = derive_key_iv(password)
    return AESGCM(key).decrypt(base64.b64decode(bundle["nonce_b64"]),
                               base64.b64decode(bundle["ct_b64"]), None)


def secure_pack(key: str, op: dict) -> str:
    import json as _json

    from pnasys_encryption_service import EncryptString

    return EncryptString(_json.dumps(op, separators=(",", ":")), key)


def secure_unpack(key: str, token: str) -> dict:
    import json as _json

    from pnasys_encryption_service import DecryptString

    return _json.loads(DecryptString(token, key))


# --- session/link code generator (exact PNASystemsKeyGenerator.py) ---

def RandomService(Minimum, Maximum) -> int:
    return Minimum + secrets.randbelow(Maximum - Minimum + 1)


def ToHexSHA256(Input: str) -> str:
    return hashlib.sha256(Input.encode("utf-8")).hexdigest()


def GetRandomNumber() -> int:
    A = 0
    B = RandomService(123821, 98169809)
    C = RandomService(838390, 67867189)
    if B == C:
        B += RandomService(1, 100)
    if B > C:
        A = round(B / C)
    else:
        A = round(C / B)
    return A


def ReverseString(String: str) -> str:
    return String[::-1]


def generate_session_key() -> str:
    from pnasys_encryption_service import GenerateEncryptionKey

    EncryptionKeyBase = GenerateEncryptionKey()
    try:
        EncryptionKeyPart1 = str(uuid.uuid8())  # exact original call
    except AttributeError:
        EncryptionKeyPart1 = str(uuid.uuid4())  # stdlib has no uuid8
    EncryptionKeyPart2 = (EncryptionKeyPart1
                          + datetime.datetime.now().strftime("%d/%m/%Y")
                          + os.getcwd() + str(GetRandomNumber()))
    EncryptionKeyPart3 = ReverseString(EncryptionKeyPart2)
    EncryptionKeyPart4 = (EncryptionKeyPart2 + "-" + EncryptionKeyBase + "-"
                          + ReverseString(EncryptionKeyBase) + "-" + EncryptionKeyPart3)
    Hash1 = ToHexSHA256(EncryptionKeyPart4)
    Hash2 = ToHexSHA256(EncryptionKeyBase)
    Hash3 = ToHexSHA256(Hash1 + EncryptionKeyBase + ReverseString(EncryptionKeyBase)
                        + ReverseString(EncryptionKeyBase) + ReverseString(Hash1))
    return (Hash1 + "=" + Hash2 + "=" + Hash3 + "=" + ReverseString(Hash3)
            + "=" + ReverseString(Hash2) + "=" + ReverseString(Hash1))


# --- identity math (unchanged spec) ---

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


def make_access_variant(uuid1: str, favcolor: str, favrest: str, uuid2: str | None = None):
    uuid2 = uuid2 or str(uuid.uuid4())
    combined2 = interleave3(sha256_hex(f"{uuid1}-{uuid2}"),
                            sha256_hex(f"{favcolor}-{uuid2}"),
                            sha256_hex(f"{favrest}-{uuid2}"))
    return combined2, uuid2, make_access_sha1024(combined2, uuid2, favcolor, favrest)


def derive_pi_encryption_key(accesskey: str) -> str:
    akh = sha256_hex(accesskey)
    h1 = sha256_hex(accesskey + akh)
    h2 = sha256_hex(akh + h1 + accesskey)
    h3 = sha256_hex(h2 + accesskey + h1)
    h4 = sha256_hex(h1 + akh + h2)
    return f"{h1}-{h3}-{h4}-{h2}"
