"""
E27 application-layer message builders.

These functions build *JSON-domain payloads only*.
They do NOT perform:
- framing
- encryption
- sequence tracking
- transport I/O

Those concerns are handled by session, presentation, and framing layers.
"""

from __future__ import annotations


def build_authenticate(*, seq: int, pin: int) -> dict:
    """
    Build an authenticate request.

    Example output:
    {
        "authenticate": {
            "seq": 110,
            "pin": 4231
        }
    }
    """
    if not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative integer")

    if not isinstance(pin, int) or not (0 <= pin <= 999999):
        raise ValueError("pin must be an integer in range 0..999999")

    return {
        "authenticate": {
            "seq": seq,
            "pin": pin,
        }
    }


def build_area_get_status(*, seq: int, session_id: int, area_id: int) -> dict:
    """
    Build an area.get_status request.

    Example output:
    {
        "seq": 111,
        "session_id": 3468417630,
        "area": {
            "get_status": {
                "area_id": 1
            }
        }
    }
    """
    if not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative integer")

    if not isinstance(session_id, int) or session_id <= 0:
        raise ValueError("session_id must be a positive integer")

    if not isinstance(area_id, int) or area_id <= 0:
        raise ValueError("area_id must be a positive integer")

    return {
        "seq": seq,
        "session_id": session_id,
        "area": {
            "get_status": {
                "area_id": area_id,
            }
        },
    }
