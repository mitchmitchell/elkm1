# test/helpers/redaction.py

from __future__ import annotations

import hashlib
from typing import Any


_SENSITIVE_KEYS = {
    # Credentials / auth
    "pin",
    "pass",
    "pass_phrase",
    "access_code",
    "installer_code",
    "user_code",
    "password",
    # Keys / crypto
    "link_enc",
    "link_hmac",
    "session_sk",
    "session_shm",
    "sk",
    "shm",
    "enc",
    "hmac",
    # Session identifiers (keep as-is in records; safe, but allow optional masking later)
    # "session_id",
}


def fingerprint_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def _fingerprint_hex(s: str) -> str | None:
    try:
        b = bytes.fromhex(s)
    except Exception:
        return None
    return fingerprint_bytes(b)


def redact_value(key: str, value: Any) -> Any:
    """Redact a potentially sensitive value.

    - For hex strings, provide a stable short fingerprint.
    - For other types, replace with <redacted>.
    """
    if value is None:
        return None

    # Prefer stable fingerprints for key-like material so runs can be compared.
    if isinstance(value, str):
        fp = _fingerprint_hex(value)
        if fp is not None:
            return {"<redacted_hex>": True, "fp12": fp, "len": len(value)}
        return "<redacted>"

    if isinstance(value, (bytes, bytearray)):
        return {"<redacted_bytes>": True, "fp12": fingerprint_bytes(bytes(value)), "len": len(value)}

    # Numbers: do not leak PINs that happen to be numeric
    return "<redacted>"


def redact_json(obj: Any) -> Any:
    """Recursively redact sensitive fields inside JSON-like structures."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in _SENSITIVE_KEYS:
                out[k] = redact_value(k, v)
            else:
                out[k] = redact_json(v)
        return out

    if isinstance(obj, list):
        return [redact_json(x) for x in obj]

    return obj


def redact_record(record: dict[str, Any]) -> dict[str, Any]:
    """Redact an emitted test record.

    This is applied to every record before it is written to JSONL/YAML.
    """
    return redact_json(record)
