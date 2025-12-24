# test/helpers/live.py

import os
import pytest

def require_live(pytestconfig):
    if not pytestconfig.getoption("--e27-live"):
        pytest.skip("live E27 tests disabled")

def load_snapshot():
    enc = os.getenv("ELK_E27_LINK_ENC")
    hmac = os.getenv("ELK_E27_LINK_HMAC")
    session = os.getenv("ELK_E27_SESSION_ID")
    if not (enc and hmac):
        return None
    return {
        "link_enc": enc,
        "link_hmac": hmac,
        "session_id": session,
    }
