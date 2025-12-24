# test/helpers/redaction.py

import hashlib

def fingerprint_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]

def redact_json(obj: dict) -> dict:
    redacted = dict(obj)
    if "pin" in redacted:
        redacted["pin"] = "<redacted>"
    if "sk" in redacted:
        redacted["sk_fp"] = fingerprint_bytes(bytes.fromhex(redacted["sk"]))
        del redacted["sk"]
    return redacted
