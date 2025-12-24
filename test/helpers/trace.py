# test/helpers/trace.py

from __future__ import annotations

def make_exchange(
    *,
    phase: str,
    request: dict | None,
    response: dict | None,
    crypto: dict | None = None,
    framing: dict | None = None,
):
    return {
        "phase": phase,
        "request": request,
        "response": response,
        "crypto": crypto,
        "framing": framing,
    }
