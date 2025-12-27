# test/helpers/trace.py

from __future__ import annotations

from typing import Any


from typing import Any


def make_exchange(
    *,
    phase: str,
    request: dict | None,
    response: dict | None,
    crypto: dict | None = None,
    framing: dict | None = None,
) -> dict:
    return {
        "phase": phase,
        "request": request,
        "response": response,
        "crypto": crypto,
        "framing": framing,
    }


def wire_frame_record(
    *,
    direction: str,
    stage: str,
    protocol_byte: int | None,
    length_field: int | None,
    crc_ok: bool | None,
    encrypted: bool | None = None,
    schema: int | None = None,
    pad_len_nibble: int | None = None,
    frame_sha256: str | None = None,
    frame_len: int | None = None,
    head_hex: str | None = None,
    tail_hex: str | None = None,
    escape_count: int | None = None,
    resync_events: int | None = None,
    ciphertext_len: int | None = None,
) -> dict[str, Any]:
    return {
        "direction": direction,
        "stage": stage,
        "link_layer": {
            "protocol_byte": f"0x{protocol_byte:02X}" if protocol_byte is not None else None,
            "length_field": length_field,
            "crc_ok": crc_ok,
            "encrypted": encrypted,
            "schema": schema,
            "pad_len_nibble": pad_len_nibble,
            "escape_count": escape_count,
            "resync_events": resync_events,
        },
        "bytes": {
            "frame_sha256": frame_sha256,
            "frame_len": frame_len,
            "frame_hex_head": head_hex,
            "frame_hex_tail": tail_hex,
        },
        "cipher": {
            "ciphertext_len": ciphertext_len,
        }
    }


def decrypt_attempt_record(
    *,
    stage: str,
    frame_sha256: str | None,
    ciphertext_len: int | None,
    pad_len: int | None,
    keys_tried: list[dict[str, Any]],
    selected_key: str | None,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "frame_sha256": frame_sha256,
        "cipher": {
            "ciphertext_len": ciphertext_len,
            "pad_len": pad_len,
        },
        "keys_tried": keys_tried,
        "selected_key": selected_key,
    }




def make_event(name: str, detail: dict[str, Any] | None = None, **fields: Any) -> tuple[str, dict[str, Any] | None]:
    """
    Build arguments for Reporter.add_event(name, detail).

    Supports either:
      - make_event("x", {"a": 1})
      - make_event("x", a=1, b=2)
      - make_event("x", {"a": 1}, b=2)  # merges

    Usage patterns:

      reporter.add_event(*make_event("parse_url.start", input_url="elk://example.local"))
      reporter.add_event(*make_event("parse_url.result", scheme=scheme, host=host, port=port))
    """
    if detail is not None and not isinstance(detail, dict):
        raise TypeError(f"make_event(detail=...) must be a dict or None, got {type(detail).__name__}")

    if detail is None and not fields:
        return (name, None)

    merged: dict[str, Any] = {}
    if detail:
        merged.update(detail)
    if fields:
        merged.update(fields)

    return (name, merged)
