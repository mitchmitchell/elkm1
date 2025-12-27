"""
E27 Session (DDR-0034 / Option A)

Responsibilities:
- Own the TCP socket lifecycle.
- Perform HELLO after connect to obtain session keys.
- Provide a robust framed receive pump using framing.DeframeState + framing.deframe_feed(state, chunk).
- Encrypt+frame outbound schema-0 payloads; deframe+decrypt inbound schema-0 payloads.
- Surface inbound decrypted JSON objects as events (callbacks) or via recv_json().

Non-responsibilities (explicit):
- API_LINK / linking (belongs to provisioning/installer flow).
- Deciding whether/when to AUTHENTICATE (privilege escalation is application-driven).
- Driving application workflows/sequences beyond send/recv primitives.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from .framing import DeframeState, deframe_feed, frame_build
from .hello import perform_hello
from .presentation import decrypt_schema0_envelope, encrypt_schema0_envelope
from . import linking

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SessionConfig:
    host: str
    port: int = 2101  # Mitch preference: non-TLS port 2101
    connect_timeout_s: float = 5.0
    io_timeout_s: float = 0.5          # socket read timeout (pump cadence)
    hello_timeout_s: float = 5.0       # overall HELLO timeout
    recv_max_bytes: int = 4096         # per socket recv() call
    protocol_default: int = 0x80       # default protocol byte for schema-0 encrypted frames


@dataclass(frozen=True)
class SessionInfo:
    session_id: int
    session_key_hex: str
    session_hmac_hex: str


class SessionState(str, Enum):
    """Internal connection lifecycle states.

    This is intentionally mechanical and policy-free.
    """

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    HELLO = "hello"
    ACTIVE = "active"


class SessionError(RuntimeError):
    """Base exception for Session failures."""


class SessionNotReadyError(SessionError):
    """Raised when an operation requires an ACTIVE session."""


class SessionIOError(SessionError):
    """Raised when the underlying transport fails."""


class SessionProtocolError(SessionError):
    """Raised when framing/crypto/JSON decoding fails."""


class Session:
    """
    Minimal E27 session connection.

    Typical usage:
        s = Session(cfg, identity=identity, link_key_hex="...")
        s.connect()          # performs HELLO and becomes ready
        s.send_json({...})   # application sends requests (including authenticate if desired)
        obj = s.recv_json()  # or call s.pump_once() to dispatch via callback
    """

    def __init__(
        self,
        cfg: SessionConfig,
        *,
        identity: linking.E27Identity,
        link_key_hex: str,
    ) -> None:
        self.cfg = cfg
        self.identity = identity
        self.link_key_hex = link_key_hex

        self.sock: Optional[socket.socket] = None
        self._deframe_state: Optional[DeframeState] = None

        self.info: Optional[SessionInfo] = None

        self.state: SessionState = SessionState.DISCONNECTED
        self.last_error: Exception | None = None

        # Event hooks (optional)
        self.on_connected: Optional[Callable[[SessionInfo], None]] = None
        self.on_message: Optional[Callable[[dict[str, Any]], None]] = None
        self.on_disconnected: Optional[Callable[[Exception | None], None]] = None

    # --------------------------
    # Connection lifecycle
    # --------------------------

    def connect(self) -> SessionInfo:
        """
        Connect TCP and perform HELLO to obtain session keys.
        """
        if self.state is not SessionState.DISCONNECTED:
            # Mechanical safety: connect() is intended to establish a new session.
            self.close()

        self.last_error = None
        self.state = SessionState.CONNECTING

        logger.info("E27 Session connecting to %s:%s", self.cfg.host, self.cfg.port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(self.cfg.connect_timeout_s)
            s.connect((self.cfg.host, self.cfg.port))
        except OSError as e:
            self.last_error = e
            self.state = SessionState.DISCONNECTED
            try:
                s.close()
            except Exception:
                pass
            raise SessionIOError(
                f"Failed to connect to {self.cfg.host}:{self.cfg.port}: {e}"
            ) from e

        # After connect, switch to pump cadence timeout.
        s.settimeout(self.cfg.io_timeout_s)
        self.sock = s
        self._deframe_state = DeframeState()

        self.state = SessionState.HELLO
        try:
            keys = perform_hello(
                sock=s,
                identity=self.identity,
                linkkey_hex=self.link_key_hex,
                timeout_s=self.cfg.hello_timeout_s,
            )
        except Exception as e:
            self.last_error = e
            # HELLO failure is a session setup failure; close and surface clearly.
            self._handle_disconnect(e)
            raise SessionProtocolError(
                f"HELLO failed for {self.cfg.host}:{self.cfg.port}: {e}"
            ) from e

        self.info = SessionInfo(
            session_id=keys.session_id,
            session_key_hex=keys.session_key_hex,
            session_hmac_hex=keys.hmac_key_hex,
        )
        self.state = SessionState.ACTIVE

        logger.info("E27 HELLO complete; session_id=%s", self.info.session_id)

        if self.on_connected:
            self.on_connected(self.info)

        return self.info

    def close(self) -> None:
        """
        Close the socket. Safe to call multiple times.
        """
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self._deframe_state = None
        self.info = None
        self.state = SessionState.DISCONNECTED

    # --------------------------
    # Transport helpers
    # --------------------------

    def _require_ready(self) -> None:
        if (
            self.state is not SessionState.ACTIVE
            or self.sock is None
            or self.info is None
            or self._deframe_state is None
        ):
            raise SessionNotReadyError(
                "Session is not ACTIVE/ready (call connect() successfully first)."
            )

    def _recv_some(self, *, max_bytes: int) -> bytes:
        """
        Read from socket; may raise TimeoutError or ConnectionError.
        Kept as a method so tests can monkeypatch it.
        """
        self._require_ready()
        assert self.sock is not None

        try:
            data = self.sock.recv(max_bytes)
        except socket.timeout as e:
            raise TimeoutError("Timed out waiting for data from the panel.") from e
        except OSError as e:
            raise SessionIOError(
                f"Socket read failed from {self.cfg.host}:{self.cfg.port}: {e}"
            ) from e

        if not data:
            raise SessionIOError(
                f"Connection closed by the panel ({self.cfg.host}:{self.cfg.port})."
            )

        return data

    def _send_all(self, data: bytes) -> None:
        self._require_ready()
        assert self.sock is not None
        try:
            self.sock.sendall(data)
        except OSError as e:
            raise SessionIOError(
                f"Socket write failed to {self.cfg.host}:{self.cfg.port}: {e}"
            ) from e

    # --------------------------
    # Framed receive pump
    # --------------------------

    def _recv_one_frame_no_crc(self, *, timeout_s: float) -> bytes:
        """
        Return the first valid frame_no_crc from the stream.

        frame_no_crc layout (per framing.deframe_feed):
            [protocol_byte][len_lo][len_hi][ciphertext...]
        """
        self._require_ready()
        assert self._deframe_state is not None

        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "Timed out waiting for a framed message from the panel."
                )

            try:
                chunk = self._recv_some(max_bytes=self.cfg.recv_max_bytes)
            except TimeoutError:
                # keep pumping until overall deadline
                continue

            logger.debug("RX raw chunk (%d bytes): %s", len(chunk), chunk.hex())

            results = deframe_feed(self._deframe_state, chunk)
            for r in results:
                if getattr(r, "ok", False):
                    logger.debug(
                        "RX frame_no_crc (%d bytes): %s",
                        len(r.frame_no_crc or b""),
                        (r.frame_no_crc or b"").hex(),
                    )
                    return r.frame_no_crc
                # CRC-bad or malformed frames: ignore and keep scanning.
                # If the framing layer provides details, emit at debug level.
                err = getattr(r, "error", None)
                if err:
                    logger.debug("Ignoring invalid frame while resyncing: %s", err)

    # --------------------------
    # Public send/recv API
    # --------------------------

    def send_json(self, obj: dict[str, Any], *, protocol_byte: Optional[int] = None) -> None:
        """
        Encrypt schema-0 payload (JSON UTF-8 bytes) and send as a framed message.
        """
        self._require_ready()
        assert self.info is not None

        payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        proto, ciphertext = encrypt_schema0_envelope(
            payload=payload,
            session_key=bytes.fromhex(self.info.session_key_hex),
            src=1,
            dest=0,
            head=0,
            envelope_seq=0,
        )

        framed = frame_build(protocol_byte=proto, data_frame=ciphertext)
        self._send_all(framed)

    def recv_json(self, *, timeout_s: float = 5.0) -> dict[str, Any]:
        """
        Receive one framed message, decrypt schema-0, parse JSON, return dict.
        """
        self._require_ready()
        assert self.info is not None

        frame_no_crc = self._recv_one_frame_no_crc(timeout_s=timeout_s)
        if len(frame_no_crc) < 3:
            raise SessionProtocolError(
                f"Received an invalid frame (too short) from {self.cfg.host}:{self.cfg.port}."
            )

        protocol_byte = frame_no_crc[0]
        ciphertext = frame_no_crc[3:]  # skip protocol + 2-byte length

        try:
            env = decrypt_schema0_envelope(
                protocol_byte=protocol_byte,
                ciphertext=ciphertext,
                session_key=bytes.fromhex(self.info.session_key_hex),
            )
        except Exception as e:
            raise SessionProtocolError(
                f"Failed to decrypt schema-0 envelope from {self.cfg.host}:{self.cfg.port}: {e}"
            ) from e

        try:
            obj = json.loads(env.payload.decode("utf-8"))
        except Exception as e:
            raise SessionProtocolError(
                f"Received invalid JSON payload from {self.cfg.host}:{self.cfg.port}: {e}"
            ) from e

        if not isinstance(obj, dict):
            raise SessionProtocolError(
                f"Expected a JSON object (dict) but received {type(obj).__name__} from {self.cfg.host}:{self.cfg.port}."
            )

        return obj

    def pump_once(self, *, timeout_s: float = 0.5) -> Optional[dict[str, Any]]:
        """
        One pump iteration: receive and dispatch exactly one message if available.

        Returns:
            The decoded JSON dict if one was received, else None on timeout.
        """
        try:
            obj = self.recv_json(timeout_s=timeout_s)
        except TimeoutError:
            return None
        except SessionNotReadyError:
            # Caller attempted to pump without a connected session.
            raise
        except (SessionIOError, SessionProtocolError) as e:
            # A transport/protocol failure means the session is no longer healthy.
            logger.warning(
                "Session pump failed (%s) in state=%s for %s:%s: %s",
                type(e).__name__,
                self.state.value,
                self.cfg.host,
                self.cfg.port,
                e,
            )
            self._handle_disconnect(e)
            raise
        except Exception as e:
            # Unexpected error: still treat as disconnect-worthy at the Session layer.
            logger.warning(
                "Unexpected session pump error (%s) in state=%s for %s:%s: %s",
                type(e).__name__,
                self.state.value,
                self.cfg.host,
                self.cfg.port,
                e,
            )
            self._handle_disconnect(e)
            raise

        if self.on_message:
            self.on_message(obj)

        return obj

    def _handle_disconnect(self, err: Exception | None) -> None:
        self.last_error = err
        try:
            self.close()
        finally:
            if self.on_disconnected:
                self.on_disconnected(err)

    def reconnect(self) -> SessionInfo:
        """Mechanical reconnect helper (no backoff/policy).

        This is intentionally a convenience wrapper around close() + connect().
        Any retry/backoff strategy belongs above the Session layer.
        """
        self.close()
        return self.connect()
