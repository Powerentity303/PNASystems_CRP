"""Session-key generator — exact logic of PNASystemsKeyGenerator.py.

The original script runs at import and prints; this module preserves every
line of that logic verbatim inside generate_session_key() (returning instead
of printing) so library/MCP use stays stdio-safe.

One documented deviation: CPython's uuid has no uuid8(), so the exact
str(uuid.uuid8()) call is attempted first and falls back to uuid4() only if
the attribute does not exist in this interpreter.
"""
from __future__ import annotations

import datetime
import hashlib
import os
import secrets
import uuid

from pnasys_encryption_service import GenerateEncryptionKey


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
    EncryptionKeyBase = GenerateEncryptionKey()
    try:
        EncryptionKeyPart1 = str(uuid.uuid8())  # exact original call
    except AttributeError:
        # CPython stdlib has no uuid8; closest equivalent.
        EncryptionKeyPart1 = str(uuid.uuid4())
    EncryptionKeyPart2 = (
        EncryptionKeyPart1
        + datetime.datetime.now().strftime("%d/%m/%Y")
        + os.getcwd()
        + str(GetRandomNumber())
    )
    EncryptionKeyPart3 = ReverseString(EncryptionKeyPart2)
    EncryptionKeyPart4 = (
        EncryptionKeyPart2
        + "-"
        + EncryptionKeyBase
        + "-"
        + ReverseString(EncryptionKeyBase)
        + "-"
        + EncryptionKeyPart3
    )
    Hash1 = ToHexSHA256(EncryptionKeyPart4)
    Hash2 = ToHexSHA256(EncryptionKeyBase)
    Hash3 = ToHexSHA256(
        Hash1
        + EncryptionKeyBase
        + ReverseString(EncryptionKeyBase)
        + ReverseString(EncryptionKeyBase)
        + ReverseString(Hash1)
    )
    FinalEncryptionKey = (
        Hash1
        + "="
        + Hash2
        + "="
        + Hash3
        + "="
        + ReverseString(Hash3)
        + "="
        + ReverseString(Hash2)
        + "="
        + ReverseString(Hash1)
    )
    return FinalEncryptionKey
