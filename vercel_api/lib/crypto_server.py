"""Server-side crypto + identity helpers (Vercel).

- ident(access_key) = SHA256(access_key) hex — queue polling identity and
  key-file basename. The raw access key is never used as a filename and is
  never logged.
- Pi-blob encryption key derivation (exact user spec):
    akh = H(accesskey); h1 = H(accesskey+akh); h2 = H(akh+h1+accesskey)
    h3 = H(h2+accesskey+h1); h4 = H(h1+akh+h2)
    encryptionkey = h1-h3-h4-h2
  The pi blob is encrypted with pnasys-encryption-service under that key
  before being stored in the key DB repo.
"""
from __future__ import annotations

import hashlib


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def ident_for(access_key: str) -> str:
    return sha256_hex(access_key)


def derive_pi_encryption_key(access_key: str) -> str:
    akh = sha256_hex(access_key)
    h1 = sha256_hex(access_key + akh)
    h2 = sha256_hex(akh + h1 + access_key)
    h3 = sha256_hex(h2 + access_key + h1)
    h4 = sha256_hex(h1 + akh + h2)
    return f"{h1}-{h3}-{h4}-{h2}"


def encrypt_pi_blob(pi_blob: str, access_key: str) -> str:
    from pnasys_encryption_service import EncryptString

    return EncryptString(pi_blob, derive_pi_encryption_key(access_key))


def decrypt_pi_blob(token: str, access_key: str) -> str:
    from pnasys_encryption_service import DecryptString

    return DecryptString(token, derive_pi_encryption_key(access_key))
