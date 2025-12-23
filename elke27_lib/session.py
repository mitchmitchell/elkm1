# elkm1/elke27_lib/session.py

"""
E27 Session Orchestrator (Phase 2)

Refactor target: move the working sequencing logic out of tools/e27_smoketest.py
into a reusable Session class, with callbacks instead of prints.

Implements the session lifecycle and routing rules defined in:
- DDR-0022: Session Lifecycle and Framed vs Unframed Traffic Handling
- DDR-0024: Session State Machine, Timeouts, and Reconnect Strategy

NOTE:
- This file assumes the existence of the E27-specific modules we created earlier:
  - framing.py (deframer/framer helpers)
  - presentation.py (encrypt/decrypt envelope)
  - linking.py (api_link exchange)
  - hello.py (hello exchange + session key decrypt)
  - encryption.py (swap_endianness and crypto helpers)
  - provisioning.py (credentials orchestration)
- It intentionally does NOT contain Home Assistant integration. That’s provisioned via callbacks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional, Any

import socket
import time

logger = logging.getLogger(__name__)

class ProvisioningRequiredError(RuntimeError):
    """Raised when credentials are required from the caller/HA provisioning flow."""

@dataclass(frozen=True)
class SessionResult:
    """
    Returned by connect_and_authenticate() when the session reaches AUTHENTICATED.

    This is intentionally small and stable. Do not include secrets beyond what is required
    for the rest of the session lifetime.
    """
    session_id: int
    user_id: Optional[int] = None
    group_id: Optional[int] = None
    installer: Optional[bool] = None

    # CSMs and other inventory fields returned by authenticate can be large;
    # provide them as an opaque dict for now.
    authenticate_payload: Optional[dict] = None


class SessionState(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    DISCOVERING = auto()
    LINKING = auto()
    HELLO = auto()
    AUTHENTICATED = auto()
    ERROR = auto()
    PROVISIONING_REQUIRED = auto()


@dataclass
class SessionConfig:
    host: str
    port: int = 2101
    connect_timeout_s: float = 5.0
    io_timeout_s: float = 5.0

    # Protocol timeouts
    discovery_timeout_s: float = 10.0
    api_link_timeout_s: float = 10.0
    hello_timeout_s: float = 10.0
    auth_timeout_s: float = 10.0

    # Reconnect/backoff
    reconnect_initial_s: float = 1.0
    reconnect_max_s: float = 30.0

    # Diagnostics
    log_raw: bool = False


class Session:
    """
    Authoritative E27 session controller.

    Public usage pattern:
      s = Session(config)
      s.on_message = ...
      s.on_error = ...
      s.on_provisioning_required = ...
      s.connect_and_authenticate(pin=1234, do_area_status=True)
    """

    def __init__(self, config: SessionConfig) -> None:
        self.cfg = config
        self.state: SessionState = SessionState.DISCONNECTED

        self.sock: Optional[socket.socket] = None

        # Session material (non-persistent by design)
        self.link_key: Optional[str] = None
        self.link_hmac: Optional[str] = None
        self.session_key: Optional[str] = None
        self.session_hmac: Optional[str] = None
        self.session_id: Optional[int] = None

        # Callbacks
        self.on_message: Optional[Callable[[dict], None]] = None
        self.on_authenticated: Optional[Callable[[], None]] = None
        self.on_provisioning_required: Optional[Callable[[], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_state_changed: Optional[Callable[[SessionState, SessionState], None]] = None
        self.on_raw_rx: Optional[Callable[[bytes], None]] = None
        self.on_raw_tx: Optional[Callable[[bytes], None]] = None

        # Provisioning bridge (set by caller)
        self.provisioning: Optional[Any] = None  # ProvisioningManager, but keep loose to avoid import cycles

    # ------------------------
    # State helpers
    # ------------------------

    def set_state(self, new_state: SessionState) -> None:
        old = self.state
        self.state = new_state
        if self.on_state_changed:
            self.on_state_changed(old, new_state)

    def _fail(self, msg: str) -> None:
        logger.error(msg)
        self.set_state(SessionState.ERROR)
        if self.on_error:
            self.on_error(msg)
        else:
            raise RuntimeError(msg)

    def require_provisioning(self, reason: str) -> None:
        # DDR-0023/0024: provisioning is user-driven, session detects need.
        self.set_state(SessionState.PROVISIONING_REQUIRED)
        if self.on_error:
            self.on_error(reason)
        if self.on_provisioning_required:
            self.on_provisioning_required()

    # ------------------------
    # Socket I/O
    # ------------------------

    def connect(self) -> None:
        if self.sock is not None:
            return
        self.set_state(SessionState.CONNECTING)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.cfg.connect_timeout_s)
        s.connect((self.cfg.host, self.cfg.port))
        s.settimeout(self.cfg.io_timeout_s)

        self.sock = s
        self.set_state(SessionState.DISCOVERING)

    def close(self) -> None:
        self.set_state(SessionState.DISCONNECTED)
        try:
            if self.sock is not None:
                self.sock.close()
        finally:
            self.sock = None

    
    def _send(self, data: bytes) -> None:
        if self.sock is None:
            self._fail("Socket is not connected.")
            return
        if self.cfg.log_raw:
            logger.debug("TX %d bytes", len(data))
            if self.on_raw_tx:
                self.on_raw_tx(data)
        self.sock.sendall(data)
    
    
    def _recv_some(self, max_bytes: int = 4096) -> bytes:
        if self.sock is None:
            self._fail("Socket is not connected.")
            return b""
        data = self.sock.recv(max_bytes)
        if self.cfg.log_raw and data:
            logger.debug("RX %d bytes", len(data))
            if self.on_raw_rx:
                self.on_raw_rx(data)
        return data
    


    # ------------------------
    # High-level flow
    # ------------------------
    
    def connect_and_authenticate(
        self,
        *,
        pin: int,
        do_area_status: bool = False,
        area_id: int = 1,
    ) -> SessionResult:
        """
        Executes the known-good sequence:
          discovery -> api_link -> hello -> authenticate
        then optionally sends area.get_status and emits on_message.
    
        Returns:
            SessionResult for the authenticated session.
        """
        from .linking import perform_api_link
        from .hello import perform_hello
    
        logger.info("Connecting to %s:%s", self.cfg.host, self.cfg.port)
        self.connect()
    
        # ---- Phase 1: discovery (unframed) ----
        self.set_state(SessionState.DISCOVERING)
        logger.debug("Waiting for discovery (ELKWC2017)...")
        discovery = self._recv_unframed_json(timeout_s=self.cfg.discovery_timeout_s, expect_key="ELKWC2017")
        nonce = discovery.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            self._fail("Discovery hello missing nonce.")
            raise RuntimeError("unreachable")
    
        logger.debug("Discovery nonce received.")
    
        # ---- Phase 2: linking (api_link) ----
        self.set_state(SessionState.LINKING)
    
        creds = None
        if self.provisioning is not None:
            creds = self.provisioning.get_credentials()
    
        if creds is None:
            logger.warning("Provisioning required: missing E27 credentials for API_LINK.")
            self.require_provisioning("Missing E27 credentials: provisioning required for API_LINK.")
            raise ProvisioningRequiredError("provisioning required")
#            raise RuntimeError("provisioning required")  # keeps type checker honest
    
        access_code, pass_phrase = creds
        try:
            logger.debug("Performing API_LINK...")
            link_key, link_hmac = perform_api_link(
                send_unframed_json=self._send_unframed_json,
                recv_framed_bytes=self._recv_some,
                nonce=nonce,
                access_code=access_code,
                pass_phrase=pass_phrase,
                timeout_s=self.cfg.api_link_timeout_s,
                log_raw=self.cfg.log_raw,
            )
        except TimeoutError:
            logger.warning("API_LINK timed out (panel silent). Likely invalid credentials.")
            self.require_provisioning("API_LINK timed out (panel silent). Credentials may be invalid.")
            raise ProvisioningRequiredError("provisioning required")
#            raise RuntimeError("provisioning required")  # keeps type checker honest
        except Exception as e:
            self._fail(f"API_LINK failed: {e}")
            raise
        finally:
            # DDR-0023: clear one-time credentials after use.
            if self.provisioning is not None:
                self.provisioning.clear_credentials()
    
        self.link_key = link_key
        self.link_hmac = link_hmac
        logger.debug("API_LINK succeeded (link credentials obtained).")
    
        # ---- Phase 3: hello (unframed) ----
        self.set_state(SessionState.HELLO)
        try:
            logger.debug("Performing HELLO...")
            session_id, session_key, session_hmac = perform_hello(
                send_unframed_json=self._send_unframed_json,
                recv_unframed_json=self._recv_unframed_json,
                link_key=self.link_key,
                timeout_s=self.cfg.hello_timeout_s,
            )
        except Exception as e:
            self._fail(f"HELLO failed: {e}")
            raise
    
        self.session_id = session_id
        self.session_key = session_key
        self.session_hmac = session_hmac
        logger.debug("HELLO succeeded (session keys obtained). session_id=%s", session_id)
    
        # ---- Phase 4: authenticate (framed+encrypted) ----
        from .message import build_authenticate, build_area_get_status
        from .presentation import encode_encrypted_message, decode_encrypted_message
        from .framing import deframe_feed, frame_build
    
        self.set_state(SessionState.AUTHENTICATED)
    
        auth_cmd = build_authenticate(seq=110, pin=pin)
        auth_cipher = encode_encrypted_message(session_key=self.session_key, payload_json=auth_cmd)
        self._send(frame_build(auth_cipher))
    
        auth_plain = self._recv_one_framed_message(
            deframe_feed=deframe_feed,
            decode_encrypted_message=decode_encrypted_message,
            timeout_s=self.cfg.auth_timeout_s,
        )
    
        if self.on_message:
            self.on_message(auth_plain)
    
        auth_body = auth_plain.get("authenticate") if isinstance(auth_plain, dict) else None
        if not isinstance(auth_body, dict):
            self._fail("Authenticate response missing 'authenticate' object.")
            raise RuntimeError("bad authenticate response")
    
        # Build structured result
        result = SessionResult(
            session_id=int(auth_body.get("session_id", self.session_id)),
            user_id=auth_body.get("user_id"),
            group_id=auth_body.get("group_id"),
            installer=auth_body.get("installer"),
            authenticate_payload=auth_plain,
        )
    
        if self.on_authenticated:
            self.on_authenticated()
    
        if do_area_status:
            cmd = build_area_get_status(seq=111, session_id=result.session_id, area_id=area_id)
            cipher = encode_encrypted_message(session_key=self.session_key, payload_json=cmd)
            self._send(frame_build(cipher))
            plain = self._recv_one_framed_message(
                deframe_feed=deframe_feed,
                decode_encrypted_message=decode_encrypted_message,
                timeout_s=self.cfg.auth_timeout_s,
            )
            if self.on_message:
                self.on_message(plain)
    
        return result
    

    # ------------------------
    # Unframed helpers (Discovery / api_link request / hello)
    # ------------------------

    def _send_unframed_json(self, obj: dict) -> None:
        import json
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self._send(data)

    def _recv_unframed_json(self, *, timeout_s: float, expect_key: Optional[str] = None) -> dict:
        """
        Reads until a full JSON object is parseable.
        Also handles the panel behavior of concatenated JSON objects (e.g., discovery sends two objects).
        """
        import json
        start = time.monotonic()
        buf = bytearray()

        while (time.monotonic() - start) < timeout_s:
            chunk = self._recv_some()
            if not chunk:
                continue
            buf.extend(chunk)

            # Fast path: try to parse entire buffer as JSON
            try:
                obj = json.loads(buf.decode("utf-8"))
                if expect_key is None:
                    return obj
                if expect_key in obj:
                    return obj
            except Exception:
                pass

            # Concatenated JSON objects: scan and parse the first object
            objs = self._split_concatenated_json(buf)
            if objs:
                for raw in objs:
                    try:
                        o = json.loads(raw.decode("utf-8"))
                    except Exception:
                        continue
                    if expect_key is None:
                        return o
                    if expect_key in o:
                        return o

        raise TimeoutError("Timed out waiting for unframed JSON response.")

    def _recv_unframed_json_bytes(self, *, timeout_s: float) -> bytes:
        """
        Variant that returns raw JSON bytes for callers that do their own parsing.
        """
        import json
        start = time.monotonic()
        buf = bytearray()

        while (time.monotonic() - start) < timeout_s:
            chunk = self._recv_some()
            if not chunk:
                continue
            buf.extend(chunk)

            objs = self._split_concatenated_json(buf)
            if objs:
                return objs[0]

            try:
                json.loads(buf.decode("utf-8"))
                return bytes(buf)
            except Exception:
                pass

        raise TimeoutError("Timed out waiting for unframed JSON bytes.")

    @staticmethod
    def _split_concatenated_json(data: bytes | bytearray) -> list[bytes]:
        """
        Parse concatenated top-level JSON objects from a byte buffer.
        Returns a list of raw JSON byte slices.
        """
        out: list[bytes] = []
        depth = 0
        in_str = False
        esc = False
        start = None

        for i, b in enumerate(data):
            ch = chr(b)
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start is not None:
                        out.append(bytes(data[start : i + 1]))
                        start = None
        return out

    # ------------------------
    # Framed helpers (Authenticated)
    # ------------------------

    def _recv_one_framed_message(
        self,
        *,
        deframe_feed: Callable[[bytes], list[Any]],
        decode_encrypted_message: Callable[..., dict],
        timeout_s: float,
    ) -> dict:
        """
        Reads from socket until one valid framed message is decoded/decrypted.
        Continues after CRC or decode errors until timeout, per DDR-0024.
        """
        start = time.monotonic()

        while (time.monotonic() - start) < timeout_s:
            chunk = self._recv_some()
            if not chunk:
                continue

            results = deframe_feed(chunk)
            for r in results:
                # Expected contract: each result has either payload_bytes or an error marker.
                payload = getattr(r, "payload", None) or getattr(r, "payload_bytes", None)
                err = getattr(r, "error", None)
                if err is not None:
                    # keep scanning
                    continue
                if not payload:
                    continue

                try:
                    plain = decode_encrypted_message(session_key=self.session_key, framed_payload=payload)
                    return plain
                except Exception:
                    # keep scanning after decrypt/parse error
                    continue

        raise TimeoutError("Timed out waiting for framed response.")
