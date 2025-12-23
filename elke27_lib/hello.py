"""
E27 hello exchange (per-TCP-connection) — cleartext JSON request/response, with
session key material decrypted via presentation layer helpers.

This module MUST NOT import cryptography primitives. All crypto operations
belong in presentation.py.

Flow:
  1) send hello JSON (clear, UNFRAMED)
  2) receive cleartext JSON response containing hello.session_id + encrypted sk/shm
  3) decrypt sk/shm using linkkey via presentation.decrypt_key_field_with_linkkey()
  4) return SessionKeys

Related DDRs:
- DDR-0019: Provisioning vs Runtime Responsibilities and Module Boundaries
- DDR-0017: Ack/Head Byte Before JSON (not used for hello response; hello is clear JSON)
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Optional

from .errors import E27ErrorContext, E27ProtocolError, E27TransportError, E27Timeout
from .linking import E27Identity, recv_cleartext_json_objects, send_unframed_json
from .presentation import decrypt_key_field_with_linkkey


@dataclass(frozen=True, slots=True)
class SessionKeys:
    """Session keys derived from hello response."""
    session_id: int
    session_key_hex: str  # 16 bytes => 32 hex chars (lowercase)
    hmac_key_hex: str     # 32 bytes => 64 hex chars (lowercase)


def build_hello_request(*, seq: int, identity: E27Identity) -> str:
    """
    Build the hello request JSON.

    Note: hello is cleartext and UNFRAMED (per your confirmed live behavior).
    """
    msg = {
        "seq": int(seq),
        "hello": {
            "mn": identity.mn,
            "sn": identity.sn,
            "fwver": identity.fwver,
            "hwver": identity.hwver,
            "osver": identity.osver,
        },
    }
    return json.dumps(msg, separators=(",", ":"))


def _select_hello_object(objs: list[dict]) -> dict:
    for obj in objs:
        if isinstance(obj, dict) and "hello" in obj and isinstance(obj["hello"], dict):
            return obj
    raise E27ProtocolError(
        "Hello response not found in cleartext JSON stream.",
        context=E27ErrorContext(phase="hello_recv"),
    )


def perform_hello(
    *,
    sock: socket.socket,
    identity: E27Identity,
    linkkey_hex: str,
    seq: int = 110,
    timeout_s: float = 5.0,
) -> SessionKeys:
    """
    Execute hello sequence for a single TCP connection.

    Raises:
      - E27Timeout on recv timeout
      - E27TransportError on socket failure
      - E27ProtocolError on malformed JSON or decrypt failure
    """
    req = build_hello_request(seq=seq, identity=identity)

    # Send clear, UNFRAMED JSON
    send_unframed_json(sock, req)

    # Receive clear, UNFRAMED JSON (may be concatenated objects)
    try:
        objs = recv_cleartext_json_objects(sock, timeout_s=timeout_s)
    except E27Timeout:
        raise
    except E27TransportError:
        raise
    except Exception as e:
        raise E27ProtocolError(
            f"Unexpected error receiving hello response: {e}",
            context=E27ErrorContext(phase="hello_recv"),
            cause=e,
        )

    hello_obj = _select_hello_object(objs)

    # Parse fields
    try:
        hello = hello_obj["hello"]
        session_id = int(hello["session_id"])
        sk_hex = str(hello["sk"])
        shm_hex = str(hello["shm"])
        err = int(hello.get("error_code", 0))
    except Exception as e:
        raise E27ProtocolError(
            f"Malformed hello response JSON: {e}",
            context=E27ErrorContext(phase="hello_parse"),
            cause=e,
        )

    if err != 0:
        raise E27ProtocolError(
            f"hello returned error_code={err}",
            context=E27ErrorContext(phase="hello_parse", detail=f"error_code={err}"),
        )

    # Decrypt session key material using presentation layer (no crypto imports here)
    try:
        session_key_bytes = decrypt_key_field_with_linkkey(
            linkkey_hex=linkkey_hex,
            ciphertext_hex=sk_hex,
        )
        hmac_key_bytes = decrypt_key_field_with_linkkey(
            linkkey_hex=linkkey_hex,
            ciphertext_hex=shm_hex,
        )
    except E27ProtocolError:
        raise
    except Exception as e:
        raise E27ProtocolError(
            f"Failed to decrypt hello session keys: {e}",
            context=E27ErrorContext(phase="hello_decrypt"),
            cause=e,
        )

    # Normalize to lowercase hex for consistency across the library
    session_key_hex = session_key_bytes.hex()
    hmac_key_hex = hmac_key_bytes.hex()

    # Light sanity checks (don’t over-assume sizes, but these are observed invariants)
    if len(session_key_bytes) != 16:
        raise E27ProtocolError(
            f"hello session key decrypted to {len(session_key_bytes)} bytes (expected 16).",
            context=E27ErrorContext(phase="hello_decrypt", detail=f"sk_len={len(session_key_bytes)}"),
        )
    if len(hmac_key_bytes) != 32:
        raise E27ProtocolError(
            f"hello hmac key decrypted to {len(hmac_key_bytes)} bytes (expected 32).",
            context=E27ErrorContext(phase="hello_decrypt", detail=f"hmac_len={len(hmac_key_bytes)}"),
        )

    return SessionKeys(
        session_id=session_id,
        session_key_hex=session_key_hex,
        hmac_key_hex=hmac_key_hex,
    )
