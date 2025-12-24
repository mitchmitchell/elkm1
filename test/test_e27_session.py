# test/test_e27_session.py
#
# Unit tests for session.py (DDR-0034 / Option A)
#
# These tests validate Session as a transport + crypto + framing boundary:
# - TCP connect lifecycle + HELLO handshake + key storage
# - framing pump uses DeframeState + deframe_feed(state, chunk)
# - send_json encrypts schema-0 and frames via frame_build, then sendall
# - recv_json deframes + decrypts schema-0 + parses JSON dict
# - pump_once dispatches on_message, handles timeout, and disconnects on errors
#
# IMPORTANT:
# - Session is NOT expected to perform API_LINK, authenticate, or workflows.
# - These tests use fakes/mocks for socket, perform_hello, framing, and crypto helpers.

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, List, Optional

import pytest

# Adjust import path if your session module lives elsewhere.
# The tests are written to be resilient by monkeypatching module-level dependencies.
from elke27_lib import session as session_mod


@dataclass
class _HelloKeys:
    session_id: int
    session_key_hex: str
    session_hmac_hex: str


class _FakeSocket:
    """
    Minimal socket fake used by Session.connect() / _recv_some() / _send_all().
    """

    def __init__(self) -> None:
        self.connected_to: Optional[tuple[str, int]] = None
        self.timeouts: List[float] = []
        self.closed: bool = False
        self.sent: List[bytes] = []
        self._recv_queue: List[bytes] = []

    def settimeout(self, t: float) -> None:
        self.timeouts.append(t)

    def connect(self, addr: tuple[str, int]) -> None:
        self.connected_to = addr

    def close(self) -> None:
        self.closed = True

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, max_bytes: int) -> bytes:
        # Session._recv_some treats b"" as socket closed.
        if not self._recv_queue:
            return b""
        return self._recv_queue.pop(0)

    def queue_recv(self, *chunks: bytes) -> None:
        self._recv_queue.extend(chunks)


@dataclass
class _DeframeResult:
    ok: bool
    frame_no_crc: bytes = b""


@dataclass
class _DecryptEnvelope:
    payload: bytes


def _make_session_ready(monkeypatch: pytest.MonkeyPatch) -> tuple[session_mod.Session, _FakeSocket]:
    """
    Create a Session instance that is already connected/ready without running connect().
    """
    cfg = session_mod.SessionConfig(host="127.0.0.1", port=2101)
    s = session_mod.Session(cfg, identity="test-client", link_key_hex="00" * 16)

    fake_sock = _FakeSocket()

    # Mark session as "ready"
    s.sock = fake_sock
    s._deframe_state = session_mod.DeframeState()
    s.info = session_mod.SessionInfo(session_id=123, session_key_hex="11" * 16, session_hmac_hex="22" * 20)

    return s, fake_sock


def test_connect_establishes_tcp_and_performs_hello(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sock = _FakeSocket()

    # Patch socket.socket(...) to return our fake.
    def _fake_socket_ctor(*args: Any, **kwargs: Any) -> _FakeSocket:
        return fake_sock

    monkeypatch.setattr(session_mod.socket, "socket", _fake_socket_ctor)

    # Patch HELLO to return deterministic keys.
    keys = _HelloKeys(session_id=7, session_key_hex="aa" * 16, session_hmac_hex="bb" * 20)

    def _fake_perform_hello(*, sock: Any, identity: str, link_key_hex: str, timeout_s: float) -> _HelloKeys:
        assert sock is fake_sock
        assert identity == "elk-client"
        assert link_key_hex == "cc" * 16
        assert timeout_s == 9.0
        return keys

    monkeypatch.setattr(session_mod, "perform_hello", _fake_perform_hello)

    cfg = session_mod.SessionConfig(host="10.0.0.5", port=2101, connect_timeout_s=3.0, io_timeout_s=0.25, hello_timeout_s=9.0)
    s = session_mod.Session(cfg, identity="elk-client", link_key_hex="cc" * 16)

    captured: dict[str, Any] = {}

    def _on_connected(info: session_mod.SessionInfo) -> None:
        captured["info"] = info

    s.on_connected = _on_connected

    info = s.connect()

    # TCP connect and timeouts were set correctly.
    assert fake_sock.connected_to == ("10.0.0.5", 2101)
    assert fake_sock.timeouts[0] == 3.0  # connect timeout
    assert fake_sock.timeouts[1] == 0.25  # io/pump cadence timeout

    # HELLO result stored as SessionInfo and returned.
    assert isinstance(info, session_mod.SessionInfo)
    assert info.session_id == 7
    assert info.session_key_hex == "aa" * 16
    assert info.session_hmac_hex == "bb" * 20
    assert s.info == info

    # DeframeState initialized.
    assert s._deframe_state is not None

    # Event hook fired.
    assert captured["info"] == info


def test_close_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    s, fake_sock = _make_session_ready(monkeypatch)

    s.close()
    assert fake_sock.closed is True
    assert s.sock is None
    assert s._deframe_state is None
    assert s.info is None

    # Calling again should not raise.
    s.close()
    assert s.sock is None


def test_send_json_encrypts_frames_and_sendall(monkeypatch: pytest.MonkeyPatch) -> None:
    s, fake_sock = _make_session_ready(monkeypatch)

    # Patch encrypt_schema0_envelope to return a protocol byte + ciphertext.
    def _fake_encrypt_schema0_envelope(*, session_key_hex: str, payload: bytes, protocol_base: int) -> tuple[int, bytes]:
        assert session_key_hex == s.info.session_key_hex
        # Ensure JSON is compact separators (",", ":") and utf-8.
        decoded = payload.decode("utf-8")
        assert decoded == '{"a":1,"b":"x"}'
        assert protocol_base == 0x80
        return 0x83, b"CIPHERTEXT"

    monkeypatch.setattr(session_mod, "encrypt_schema0_envelope", _fake_encrypt_schema0_envelope)

    # Patch frame_build to create deterministic framed bytes.
    def _fake_frame_build(*, protocol_byte: int, data_frame: bytes) -> bytes:
        assert protocol_byte == 0x83
        assert data_frame == b"CIPHERTEXT"
        return b"FRAMED:" + bytes([protocol_byte]) + data_frame

    monkeypatch.setattr(session_mod, "frame_build", _fake_frame_build)

    s.send_json({"a": 1, "b": "x"})
    assert fake_sock.sent == [b"FRAMED:" + b"\x83" + b"CIPHERTEXT"]


def test_recv_json_deframes_decrypts_and_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    s, _ = _make_session_ready(monkeypatch)

    # Provide a valid frame_no_crc: [proto][len_lo][len_hi][ciphertext...]
    monkeypatch.setattr(s, "_recv_one_frame_no_crc", lambda *, timeout_s: b"\x84\x05\x00" + b"ABCDE")

    def _fake_decrypt_schema0_envelope(*, session_key_hex: str, protocol_byte: int, ciphertext: bytes) -> _DecryptEnvelope:
        assert session_key_hex == s.info.session_key_hex
        assert protocol_byte == 0x84
        assert ciphertext == b"ABCDE"
        return _DecryptEnvelope(payload=b'{"ok":true,"n":2}')

    monkeypatch.setattr(session_mod, "decrypt_schema0_envelope", _fake_decrypt_schema0_envelope)

    obj = s.recv_json(timeout_s=1.0)
    assert obj == {"ok": True, "n": 2}


def test_recv_json_rejects_short_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    s, _ = _make_session_ready(monkeypatch)
    monkeypatch.setattr(s, "_recv_one_frame_no_crc", lambda *, timeout_s: b"\x80\x00")  # too short

    with pytest.raises(ValueError, match="frame_no_crc too short"):
        s.recv_json(timeout_s=0.1)


def test_recv_json_rejects_non_object_json(monkeypatch: pytest.MonkeyPatch) -> None:
    s, _ = _make_session_ready(monkeypatch)
    monkeypatch.setattr(s, "_recv_one_frame_no_crc", lambda *, timeout_s: b"\x81\x03\x00" + b"XYZ")

    monkeypatch.setattr(
        session_mod,
        "decrypt_schema0_envelope",
        lambda *, session_key_hex, protocol_byte, ciphertext: _DecryptEnvelope(payload=b"[1,2,3]"),
    )

    with pytest.raises(ValueError, match="expected JSON object"):
        s.recv_json(timeout_s=0.2)


def test_recv_json_rejects_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    s, _ = _make_session_ready(monkeypatch)
    monkeypatch.setattr(s, "_recv_one_frame_no_crc", lambda *, timeout_s: b"\x81\x03\x00" + b"XYZ")

    monkeypatch.setattr(
        session_mod,
        "decrypt_schema0_envelope",
        lambda *, session_key_hex, protocol_byte, ciphertext: _DecryptEnvelope(payload=b'{"unterminated":'),
    )

    with pytest.raises(ValueError, match="invalid JSON payload"):
        s.recv_json(timeout_s=0.2)


def test_recv_one_frame_no_crc_uses_deframe_state_and_feed(monkeypatch: pytest.MonkeyPatch) -> None:
    s, _ = _make_session_ready(monkeypatch)

    # Make _recv_some return two chunks. The first yields no OK frames, second yields an OK frame.
    chunks = [b"chunk1", b"chunk2"]

    def _fake_recv_some(*, max_bytes: int) -> bytes:
        assert max_bytes == s.cfg.recv_max_bytes
        return chunks.pop(0)

    monkeypatch.setattr(s, "_recv_some", _fake_recv_some)

    feed_calls: list[tuple[Any, bytes]] = []

    def _fake_deframe_feed(state: Any, chunk: bytes) -> list[_DeframeResult]:
        # Must be called with canonical state object and the chunk.
        feed_calls.append((state, chunk))
        if chunk == b"chunk1":
            # Simulate CRC-bad frame and/or incomplete parse.
            return [_DeframeResult(ok=False)]
        # Second chunk returns a valid frame.
        return [_DeframeResult(ok=True, frame_no_crc=b"\x80\x01\x00" + b"Z")]

    monkeypatch.setattr(session_mod, "deframe_feed", _fake_deframe_feed)

    frame = s._recv_one_frame_no_crc(timeout_s=0.5)
    assert frame == b"\x80\x01\x00Z"

    # Ensure DeframeState instance was used and deframe_feed called twice.
    assert len(feed_calls) == 2
    assert feed_calls[0][0] is s._deframe_state
    assert feed_calls[0][1] == b"chunk1"
    assert feed_calls[1][0] is s._deframe_state
    assert feed_calls[1][1] == b"chunk2"


def test_pump_once_timeout_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    s, _ = _make_session_ready(monkeypatch)

    def _fake_recv_json(*, timeout_s: float) -> dict[str, Any]:
        raise TimeoutError("socket timeout")

    monkeypatch.setattr(s, "recv_json", _fake_recv_json)

    assert s.pump_once(timeout_s=0.01) is None


def test_pump_once_dispatches_on_message(monkeypatch: pytest.MonkeyPatch) -> None:
    s, _ = _make_session_ready(monkeypatch)

    monkeypatch.setattr(s, "recv_json", lambda *, timeout_s: {"hello": "world"})

    captured: list[dict[str, Any]] = []
    s.on_message = lambda obj: captured.append(obj)

    out = s.pump_once(timeout_s=0.2)
    assert out == {"hello": "world"}
    assert captured == [{"hello": "world"}]


def test_pump_once_disconnects_and_emits_on_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    s, fake_sock = _make_session_ready(monkeypatch)

    class Boom(Exception):
        pass

    def _fake_recv_json(*, timeout_s: float) -> dict[str, Any]:
        raise Boom("decrypt failed")

    monkeypatch.setattr(s, "recv_json", _fake_recv_json)

    disconnected: dict[str, Any] = {"called": False, "err": None}

    def _on_disconnected(err: Exception | None) -> None:
        disconnected["called"] = True
        disconnected["err"] = err

    s.on_disconnected = _on_disconnected

    with pytest.raises(Boom):
        s.pump_once(timeout_s=0.2)

    # Session should have been closed and callback fired.
    assert s.sock is None
    assert s.info is None
    assert s._deframe_state is None
    assert fake_sock.closed is True

    assert disconnected["called"] is True
    assert isinstance(disconnected["err"], Boom)
