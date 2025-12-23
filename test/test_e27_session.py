# elkm1/test/e27_test_session.py

import types
import sys
import pytest


def _install_fake_module(monkeypatch, fqname: str, attrs: dict):
    """
    Install a fake module into sys.modules so that Session's lazy imports
    (from .linking import ..., etc.) resolve without needing real protocol code.
    """
    mod = types.ModuleType(fqname)
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, fqname, mod)
    return mod


def test_session_provisioning_required_when_missing_credentials(monkeypatch):
    # Import here so test suite can collect even if partial tree exists.
    from elke27_lib.session import Session, SessionConfig, SessionState
    from elke27_lib.provisioning import ProvisioningManager

    cfg = SessionConfig(host="127.0.0.1")
    s = Session(cfg)

    prov = ProvisioningManager()
    s.provisioning = prov

    # Prevent real network use.
    monkeypatch.setattr(s, "connect", lambda: s.set_state(SessionState.DISCOVERING))

    # Make discovery succeed.
    monkeypatch.setattr(
        s,
        "_recv_unframed_json",
        lambda timeout_s, expect_key=None: {"ELKWC2017": "Hello", "nonce": "deadbeef"},
    )

    # Track provisioning callback.
    seen = {"called": False}
    s.on_provisioning_required = lambda: seen.__setitem__("called", True)

    # Run (will fail before api_link because creds missing)
    from elke27_lib.session import ProvisioningRequiredError

    with pytest.raises(ProvisioningRequiredError):
        s.connect_and_authenticate(pin=1234, do_area_status=False)

    assert s.state == SessionState.PROVISIONING_REQUIRED
    assert seen["called"] is True


def test_session_happy_path_authenticate_and_optional_area_status(monkeypatch):
    from elke27_lib.session import Session, SessionConfig, SessionState
    from elke27_lib.provisioning import ProvisioningManager

    # --- Fake protocol modules used by Session.connect_and_authenticate() ---
    # linking.perform_api_link(...)
    def fake_perform_api_link(*, send_unframed_json, recv_framed_bytes, nonce, access_code, pass_phrase, timeout_s, log_raw):
        assert nonce == "nonce123"
        assert access_code == "12345678"
        assert pass_phrase == "my pass phrase"
        return ("LINKKEY0123456789ABCDEF0123456789", "LINKHMAC0123456789ABCDEF0123456789ABCDEF")

    # hello.perform_hello(...)
    def fake_perform_hello(*, send_unframed_json, recv_unframed_json, link_key, timeout_s):
        assert link_key.startswith("LINKKEY")
        return (424242, "SESSIONKEY0123456789ABCDEF0123456789", "SESSIONHMAC0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

    # message builders
    def fake_build_authenticate(seq, pin):
        return {"authenticate": {"seq": seq, "pin": pin}}

    def fake_build_area_get_status(seq, session_id, area_id):
        return {"seq": seq, "session_id": session_id, "area": {"get_status": {"area_id": area_id}}}

    # presentation encode/decode
    def fake_encode_encrypted_message(*, session_key, payload_json):
        assert session_key.startswith("SESSIONKEY")
        # return bytes that framing will "wrap"
        return b"CIPHERTEXT:" + repr(payload_json).encode("utf-8")

    def fake_decode_encrypted_message(*, session_key, framed_payload):
        # In this test, we don't actually encrypt; return dict based on marker.
        if b"authenticate" in framed_payload:
            return {"authenticate": {"error_code": 0}}
        if b"get_status" in framed_payload:
            return {"area": {"get_status": {"area_id": 1, "error_code": 0}}, "seq": 111}
        return {"unknown": True}

    # framing helpers
    def fake_frame_build(payload_bytes: bytes) -> bytes:
        return b"FRAME:" + payload_bytes

    # deframe_feed returns a list of objects with .payload_bytes and .error
    class _DeframeResult:
        def __init__(self, payload_bytes=None, error=None):
            self.payload_bytes = payload_bytes
            self.error = error

    # This fake deframer just emits one "payload" per call with the data given
    def fake_deframe_feed(chunk: bytes):
        # Expect chunk already includes b"FRAME:" prefix in this test harness.
        if chunk.startswith(b"FRAME:"):
            return [_DeframeResult(payload_bytes=chunk[len(b"FRAME:"):], error=None)]
        return [_DeframeResult(payload_bytes=None, error="not_a_frame")]

    # Install fakes under the exact module paths Session imports.
    _install_fake_module(monkeypatch, "elke27_lib.linking", {"perform_api_link": fake_perform_api_link})
    _install_fake_module(monkeypatch, "elke27_lib.hello", {"perform_hello": fake_perform_hello})
    _install_fake_module(
        monkeypatch,
        "elke27_lib.message",
        {"build_authenticate": fake_build_authenticate, "build_area_get_status": fake_build_area_get_status},
    )
    _install_fake_module(
        monkeypatch,
        "elke27_lib.presentation",
        {"encode_encrypted_message": fake_encode_encrypted_message, "decode_encrypted_message": fake_decode_encrypted_message},
    )
    _install_fake_module(monkeypatch, "elke27_lib.framing", {"deframe_feed": fake_deframe_feed, "frame_build": fake_frame_build})

    # --- Build Session + Provisioning ---
    cfg = SessionConfig(host="127.0.0.1")
    s = Session(cfg)

    prov = ProvisioningManager()
    prov.supply_credentials("12345678", "my pass phrase")
    s.provisioning = prov

    # Prevent real network use.
    monkeypatch.setattr(s, "connect", lambda: s.set_state(SessionState.DISCOVERING))

    # Provide discovery response (nonce)
    monkeypatch.setattr(
        s,
        "_recv_unframed_json",
        lambda timeout_s, expect_key=None: {"ELKWC2017": "Hello", "nonce": "nonce123"},
    )

    # Capture outbound bytes (auth + area status frames)
    tx = []
    monkeypatch.setattr(s, "_send", lambda data: tx.append(data))

    # Provide inbound framed responses by monkeypatching _recv_some.
    # Session._recv_one_framed_message reads chunks then passes to deframe_feed.
    rx_queue = [
        b"FRAME:" + b"CIPHERTEXT:" + b"{'authenticate': {'seq': 110, 'pin': 4231}}",
        b"FRAME:" + b"CIPHERTEXT:" + b"{'seq': 111, 'session_id': 424242, 'area': {'get_status': {'area_id': 1}}}",
    ]

    def fake_recv_some(max_bytes=4096):
        if rx_queue:
            return rx_queue.pop(0)
        return b""

    monkeypatch.setattr(s, "_recv_some", fake_recv_some)

    # Capture delivered messages
    msgs = []
    s.on_message = lambda obj: msgs.append(obj)

    auth_called = {"called": False}
    s.on_authenticated = lambda: auth_called.__setitem__("called", True)

    # Execute flow
    result = s.connect_and_authenticate(pin=4231, do_area_status=True, area_id=1)

    assert result.session_id == 424242
    assert s.state == SessionState.AUTHENTICATED
    assert auth_called["called"] is True

    # Should have received both messages
    assert any("authenticate" in m for m in msgs)
    assert any(m.get("area", {}).get("get_status", {}).get("area_id") == 1 for m in msgs)

    # Should have sent two framed payloads (auth + area status)
    assert len(tx) == 2
    assert tx[0].startswith(b"FRAME:")
    assert tx[1].startswith(b"FRAME:")
