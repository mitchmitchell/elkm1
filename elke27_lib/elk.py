"""
elk.py — High-level facade for interacting with an Elk E27 panel.

Elk kernel (Pattern 1: feature modules)

Goals:
- elk.py stays stable as new message types are added.
- Features register:
    - inbound handlers (dispatcher routes)
    - outbound request builders (request registry)
- No outbound policy enforcement (by design for this phase).
  "No writes" is achieved simply by not registering write request builders.

Kernel responsibilities:
- Own Session, Dispatcher, PanelState, pending registry, event queue.
- Provide register_handler()/register_request()/request() APIs for features.
- Wire Session -> Elk -> Dispatcher.
- Stamp event headers and enqueue via emit(evt, ctx).

Design goals (per user requirements)
- All example programs should access the panel through the Elk object.
- Elk.discover() delegates to discovery.AIOELKDiscovery.async_scan()
- Elk.link() performs provisioning-time API_LINK via linking.perform_api_link()
- Elk.connect() creates a session.Session, performs HELLO, and confirms ACTIVE
- Linking and authentication remain explicit operations (linking is provisioning; auth is out-of-scope here)

Notes
- This module intentionally keeps a small surface area.
- It stores the selected panel + identity after link() so connect() only needs link keys.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import discovery
from . import linking
from . import session as session_mod
from .dispatcher import DispatchContext, Dispatcher, PendingRequest, RouteKey
from .events import (
    DispatchRoutingError,
    Event,
    UNSET_AT,
    UNSET_CLASSIFICATION,
    UNSET_ROUTE,
    UNSET_SEQ,
    UNSET_SESSION_ID,
    stamp_event,
)
from .states import PanelState


RequestBuilder = Callable[..., Mapping[str, Any]]  # returns payload dict


class RequestRegistry:
    """
    Maps a route key (domain,name) to a request payload builder callable.

    No policy enforcement here: if it's registered, it is allowed by definition.
    """

    def __init__(self) -> None:
        self._builders: Dict[RouteKey, RequestBuilder] = {}

    def register(self, route: RouteKey, builder: RequestBuilder) -> None:
        self._builders[route] = builder

    def get(self, route: RouteKey) -> Optional[RequestBuilder]:
        return self._builders.get(route)

    def require(self, route: RouteKey) -> RequestBuilder:
        b = self._builders.get(route)
        if b is None:
            raise KeyError(f"No request builder registered for route {route!r}")
        return b


class ElkError(RuntimeError):
    """Base exception for Elk facade failures."""


class ElkNotLinkedError(ElkError):
    """Raised when connect() is called before link() established identity/panel context."""


class ElkInvalidPanelError(ElkError):
    """Raised when a panel entry is missing required connection fields."""


@dataclass(frozen=True, slots=True)
class DiscoverResult:
    """Wrapper for discovery results to keep the public contract explicit."""
    panels: List[discovery.ElkSystem]


@dataclass(frozen=True, slots=True)
class E27LinkKeys:
    """
    Link credentials returned by provisioning (API_LINK).

    This facade type exists to give elk.py a stable return shape even if
    linking.perform_api_link() returns a tuple internally.
    """
    tempkey_hex: str
    linkkey_hex: str
    linkhmac_hex: str


def _panel_host_port(panel: discovery.ElkSystem | Mapping[str, Any]) -> tuple[str, int]:
    """
    Extract host/port from a discovery panel entry.

    Supports:
      - discovery.ElkSystem (preferred)
      - dict-like panel entries with keys {ip_address/host/ip} and {port}
    """
    if isinstance(panel, discovery.ElkSystem):
        host = panel.ip_address
        port = int(panel.port)
        return host, port

    host = panel.get("ip_address") or panel.get("host") or panel.get("ip") or panel.get("address")
    if not host or not isinstance(host, str):
        raise ElkInvalidPanelError(f"Discovered panel entry missing host/ip: {panel!r}")

    port = panel.get("port", 2101)
    if not isinstance(port, int) or port <= 0 or port > 65535:
        raise ElkInvalidPanelError(f"Discovered panel entry has invalid port={port!r}: {panel!r}")

    return host, port


def _identity_string(identity: linking.E27Identity) -> str:
    """
    Session HELLO identity string.
    Keep stable and deterministic; content is not security-sensitive.
    """
    # Prefer a simple stable identifier; do not embed access code or passphrase.
    return f"{identity.mn}:{identity.sn}"


class Elk:
    """
    High-level facade + kernel for E27.

    Lifecycle:
      1) panels = (await Elk.discover()).panels
      2) link_keys = await elk.link(panels[0], identity, credentials)
      3) await elk.connect(link_keys)  # creates Session, HELLO, ACTIVE
      4) elk.request(...) and/or consume elk.drain_events()

    Dispatcher is synchronous and routes inbound messages to registered handlers.
    """

    DEFAULT_FEATURES: Sequence[str] = (
        "elke27_lib.features.ctrl",
        "elke27_lib.features.area",
    )

    def __init__(
        self,
        *,
        now_monotonic: Callable[[], float] = time.monotonic,
        event_queue_maxlen: int = 0,  # 0 means unbounded deque
        features: Optional[Sequence[str]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._log = logger or logging.getLogger(__name__)
        self.now = now_monotonic

        # Facade-held context for connect()
        self._panel: Optional[discovery.ElkSystem | Dict[str, Any]] = None
        self._identity: Optional[linking.E27Identity] = None

        # Kernel-owned components
        self._session: Optional[session_mod.Session] = None
        self.state = PanelState()
        self.dispatcher = Dispatcher()
        self.requests = RequestRegistry()
        self._events: Deque[Event] = deque(maxlen=(event_queue_maxlen or None))
        self._seq: int = 1

        # Always register dispatcher error envelope handler
        self.register_handler(("__error__", "__all__"), self._handle_dispatch_error_envelope)

        # Load feature modules (keep elk.py stable)
        self.load_features(features if features is not None else self.DEFAULT_FEATURES)

    @property
    def panel(self) -> Optional[discovery.ElkSystem | Dict[str, Any]]:
        return self._panel

    @property
    def identity(self) -> Optional[linking.E27Identity]:
        return self._identity

    @property
    def session(self) -> session_mod.Session:
        if self._session is None:
            raise ElkError("No active Session. Call connect() successfully first.")
        return self._session

    # -------------------------
    # Discovery / Provisioning / Connect facade
    # -------------------------

    @classmethod
    async def discover(cls, *, timeout: int = 10, address: str | None = None) -> DiscoverResult:
        """
        Elk.discover uses the discovery.py module to find a list of discovered panels and
        returns the list with the data returned by discovery.AIOELKDiscovery.async_scan().
        """
        try:
            scanner = discovery.AIOELKDiscovery()
            panels = await scanner.async_scan(timeout=timeout, address=address)
        except Exception as e:
            raise ElkError(f"Discovery failed: {e}") from e

        if panels is None:
            panels = []
        if not isinstance(panels, list):
            raise ElkError(f"Discovery returned unexpected type {type(panels).__name__}; expected list.")

        out: List[discovery.ElkSystem] = []
        for i, p in enumerate(panels):
            if isinstance(p, discovery.ElkSystem):
                out.append(p)
            else:
                raise ElkError(f"Discovery returned unexpected entry at index {i}: {p!r}")

        return DiscoverResult(panels=out)

    async def link(
        self,
        panel: discovery.ElkSystem | Dict[str, Any],
        identity: linking.E27Identity,
        credentials: Any,
        *,
        timeout_s: float = 10.0,
    ) -> E27LinkKeys:
        """
        Elk.link accepts one element of the list returned by Elk.discover plus
        linking.E27Identity and linking.E27Credentials (accesscode + passphrase)
        and returns E27LinkKeys.

        This is provisioning-time API_LINK; it is explicitly outside Session responsibility.
        """
        host, port = _panel_host_port(panel)

        if identity is None:
            raise ElkError("link(): identity is required.")
        if credentials is None:
            raise ElkError("link(): credentials are required.")

        # We expect credentials.access_code and credentials.passphrase (per requirement).
        access_code = getattr(credentials, "access_code", None) or getattr(credentials, "accesscode", None)
        passphrase = getattr(credentials, "passphrase", None)

        if not isinstance(access_code, str) or not access_code:
            raise ElkError("link(): credentials.access_code (string) is required.")
        if not isinstance(passphrase, str) or not passphrase:
            raise ElkError("link(): credentials.passphrase (string) is required.")

        def _do_link_sync() -> E27LinkKeys:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(float(timeout_s))
                sock.connect((host, port))

                # Wait for discovery hello/nonce (cleartext)
                nonce = linking.wait_for_discovery_nonce(sock, timeout_s=float(timeout_s))

                # Perform API_LINK. Existing library signature is sock-based; newer wrappers may differ.
                try:
                    tempkey_hex, linkkey_hex, linkhmac_hex = linking.perform_api_link(
                        sock=sock,
                        identity=identity,
                        access_code=access_code,
                        passphrase=passphrase,
                        mn_for_hash=identity.mn,
                        discovery_nonce=nonce,
                        seq=110,
                        timeout_s=float(timeout_s),  # may be accepted in updated linking.py
                    )
                except TypeError:
                    # Backward signature (no timeout_s kw)
                    tempkey_hex, linkkey_hex, linkhmac_hex = linking.perform_api_link(
                        sock=sock,
                        identity=identity,
                        access_code=access_code,
                        passphrase=passphrase,
                        mn_for_hash=identity.mn,
                        discovery_nonce=nonce,
                        seq=110,
                    )

                return E27LinkKeys(
                    tempkey_hex=str(tempkey_hex),
                    linkkey_hex=str(linkkey_hex),
                    linkhmac_hex=str(linkhmac_hex),
                )
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        try:
            link_keys = await asyncio.to_thread(_do_link_sync)
        except Exception as e:
            raise ElkError(f"Linking failed for {host}:{port}: {e}") from e

        # Store context so connect() only needs link keys
        self._panel = panel
        self._identity = identity

        return link_keys

    async def connect(
        self,
        link_keys: E27LinkKeys,
        *,
        session_config: Optional[session_mod.SessionConfig] = None,
    ) -> session_mod.SessionState:
        """
        Elk.connect accepts E27LinkKeys, creates/stores a session.Session, performs HELLO,
        and returns the session state (confirming ACTIVE).
        """
        if self._panel is None or self._identity is None:
            raise ElkNotLinkedError("connect() requires prior link() to establish panel + identity context.")

        host, port = _panel_host_port(self._panel)

        if not isinstance(link_keys, E27LinkKeys):
            # Allow duck-typed link keys (e.g., linking.E27LinkKeys in a future refactor)
            lk = getattr(link_keys, "linkkey_hex", None) or getattr(link_keys, "link_key_hex", None)
            if not isinstance(lk, str) or not lk:
                raise ElkError("connect(): link_keys must provide linkkey_hex/link_key_hex (string).")
            link_key_hex = lk
        else:
            link_key_hex = link_keys.linkkey_hex

        cfg = session_config or session_mod.SessionConfig(host=host, port=port)

        s = session_mod.Session(cfg=cfg, identity=self._identity, link_key_hex=link_key_hex)

        # Wire callbacks before connecting so HELLO path can report, if needed.
        s.on_message = self._on_message

        def _do_connect_sync() -> session_mod.SessionInfo:
            return s.connect()

        try:
            await asyncio.to_thread(_do_connect_sync)
        except Exception as e:
            raise ElkError(f"Session connect failed for {host}:{port}: {e}") from e

        self._session = s

        if s.state != session_mod.SessionState.ACTIVE:
            raise ElkError(f"Session connect completed but session.state is {s.state!r}, not ACTIVE.")

        self.state.panel.session_id = s.info.session_id if s.info is not None else self.state.panel.session_id

        return s.state

    async def close(self) -> None:
        """Close any active session. Idempotent."""
        if self._session is None:
            return

        s = self._session
        self._session = None

        def _do_close_sync() -> None:
            s.close()

        try:
            await asyncio.to_thread(_do_close_sync)
        except Exception as e:
            self._log.warning("Elk.close(): session close failed: %s", e, exc_info=True)

    # -------------------------
    # Feature loading
    # -------------------------

    def load_features(self, modules: Sequence[str]) -> None:
        """Import each module and invoke its register(elk) function."""
        for modname in modules:
            mod = importlib.import_module(modname)
            reg = getattr(mod, "register", None)
            if reg is None or not callable(reg):
                raise RuntimeError(f"Feature module {modname!r} has no callable register(elk) function")
            reg(self)

    # -------------------------
    # Registration surface for features
    # -------------------------

    def register_handler(self, route: RouteKey, handler: Callable[[Mapping[str, Any], DispatchContext], bool]) -> None:
        self.dispatcher.register(route, handler)

    def register_request(self, route: RouteKey, builder: RequestBuilder) -> None:
        self.requests.register(route, builder)

    # -------------------------
    # Session -> Elk -> Dispatcher wiring
    # -------------------------

    def _on_message(self, msg: Mapping[str, Any]) -> None:
        """
        Hot path: keep this fast.

        - Update PanelState (session_id, last_message_at)
        - Dispatcher.dispatch(msg)
        - (Optional) handlers may emit events via elk.emit(...)
        """
        sid = msg.get("session_id")
        if isinstance(sid, int):
            self.state.panel.session_id = sid

        self.state.panel.last_message_at = self.now()

        self._log.debug("Inbound message: %s", msg)

        # Dispatcher handles routing + correlation + dispatch-error envelopes.
        self.dispatcher.dispatch(msg)

    # -------------------------
    # Outbound requests
    # -------------------------

    def request(self, route: RouteKey, /, *, pending: bool = True, opaque: Any = None, **kwargs: Any) -> int:
        """
        Public outbound API: build payload via registry and send.

        pending=True:
          - Registers a PendingRequest with Dispatcher for seq-first correlation.
        """
        builder = self.requests.require(route)
        payload = builder(**kwargs)
        domain, name = route
        return self._send_request(domain, name, payload, pending=pending, opaque=opaque, expected_route=route)

    def _next_seq(self) -> int:
        s = self._seq
        self._seq += 1
        return s

    def _send_request(
        self,
        domain: str,
        name: str,
        payload: Mapping[str, Any],
        *,
        pending: bool,
        opaque: Any,
        expected_route: Optional[RouteKey],
    ) -> int:
        """
        Mechanical request sender (no policy enforcement in this phase):
        - assigns seq
        - adds session_id if known
        - sends via Session.send_json()
        - optionally registers pending correlation by seq
        """
        seq = self._next_seq()

        msg: Dict[str, Any] = {"seq": seq}
        if self.state.panel.session_id is not None:
            msg["session_id"] = self.state.panel.session_id

        if isinstance(payload, Mapping):
            msg[domain] = {name: dict(payload)}
        else:
            msg[domain] = {name: payload}

        self._log.debug("Sending request %s.%s seq=%s msg=%s", domain, name, seq, msg)

        # Register pending correlation before send to reduce race window
        if pending:
            self.dispatcher.add_pending(
                PendingRequest(
                    seq=seq,
                    expected_route=expected_route,
                    created_at=self.now(),
                    opaque=opaque,
                )
            )

        try:
            self.session.send_json(msg)  # Session is synchronous by design
        except Exception as e:
            raise ElkError(f"Failed to send request {domain}.{name} seq={seq}: {e}") from e

        return seq

    # -------------------------
    # Event emission + queue
    # -------------------------

    def emit(self, evt: Event, *, ctx: DispatchContext) -> None:
        stamped = stamp_event(
            evt,
            at=self.now(),
            seq=ctx.seq,
            classification=ctx.classification,
            route=ctx.route,
            session_id=ctx.session_id if ctx.session_id is not None else self.state.panel.session_id,
        )
        self._log.debug("Emit event: %s", stamped)
        self._events.append(stamped)

    def drain_events(self) -> list[Event]:
        out: list[Event] = list(self._events)
        self._events.clear()
        return out

    def iter_events(self) -> Iterable[Event]:
        return iter(self._events)

    # -------------------------
    # Dispatcher error envelope handler
    # -------------------------

    def _handle_dispatch_error_envelope(self, msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        err_root = msg.get("__error__")
        if not isinstance(err_root, Mapping) or not err_root:
            return False

        code = next(iter(err_root.keys()))
        detail = err_root.get(code)
        if not isinstance(detail, Mapping):
            return False

        message = detail.get("message")
        keys = detail.get("keys")
        severity = detail.get("severity")

        evt = DispatchRoutingError(
            kind=DispatchRoutingError.KIND,
            at=UNSET_AT,
            seq=UNSET_SEQ,
            classification=UNSET_CLASSIFICATION,
            route=UNSET_ROUTE,
            session_id=UNSET_SESSION_ID,
            code=str(code),
            message=str(message) if isinstance(message, str) else "Dispatcher routing error",
            keys=tuple(keys) if isinstance(keys, list) else (),
            severity=str(severity) if isinstance(severity, str) else "warning",
        )
        self.emit(evt, ctx=ctx)
        return True
