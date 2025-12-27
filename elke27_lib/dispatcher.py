"""
E27 JSON Dispatcher (Skeleton)

Key points (DDR-0036 aligned):
- Input: msg is a JSON object (dict) emitted by Session.recv_json()/pump_once()/on_message.
- Route extraction is deterministic:
    - domain = the only non-meta root key (meta keys: seq, session_id)
    - name   = if msg[domain] is a dict with exactly one key -> that key
               else fall back to "__root__"/"__empty__"/"__value__" with DispatchError(s)
  NOTE: The inner value under the command key may be a multi-key dict of parameters. That is expected.
- Broadcast vs directed classification is based ONLY on root seq:
    - seq == 0 => BROADCAST
    - seq > 0  => DIRECTED
    - missing  => UNKNOWN (no error; hello/bootstrap often lack root seq)
    - invalid/negative => UNKNOWN + ERR_INVALID_SEQ
- Seq correlation (optional) is seq-first and route-second. Dispatcher does not assume response route == request route.
- No nested-seq heuristics. Hello/bootstrap messages remain routable but not correlatable unless root seq exists.
- Dispatcher never raises for unknown/ambiguous JSON shapes; it only raises for programmer error (non-mapping input).
- Reserved error channel: ("__error__", "<error_code>") and ("__error__", "__all__")
  Error handlers receive an *error envelope message* (not the original msg) so they don't have to re-derive details.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple


RouteKey = Tuple[str, str]


class MessageKind(str, Enum):
    UNKNOWN = "UNKNOWN"
    DIRECTED = "DIRECTED"
    BROADCAST = "BROADCAST"


class DispatchSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class DispatchError:
    code: str
    message: str
    domain: Optional[str] = None
    name: Optional[str] = None
    keys: Tuple[str, ...] = ()
    severity: DispatchSeverity = DispatchSeverity.WARNING


@dataclass(frozen=True)
class PendingRequest:
    """
    Minimal pending request record. Seq correlation is seq-first and route-second.
    Policy (timeouts/retries/backoff) belongs above Dispatcher.
    """
    seq: int
    expected_route: Optional[RouteKey] = None
    created_at: Optional[float] = None
    opaque: Any = None


@dataclass(frozen=True)
class DispatchContext:
    """
    Diagnostics-only context. No policy.
    """
    kind: MessageKind
    seq: Optional[int]
    session_id: Optional[int]
    route: RouteKey
    classification: str  # "BROADCAST" | "RESPONSE" | "UNSOLICITED" | "UNKNOWN"
    response_match: Optional[PendingRequest] = None
    raw_route: Optional[RouteKey] = None  # original route before any error routing (usually same as route)


@dataclass
class DispatchResult:
    route: RouteKey
    kind: MessageKind
    seq: Optional[int]
    session_id: Optional[int]
    classification: str
    response_match: Optional[PendingRequest] = None
    errors: List[DispatchError] = field(default_factory=list)
    handled: bool = False


# Handler signature:
# Return True means "this handler recognized/handled it" (fan-out still continues).
DispatchHandler = Callable[[Mapping[str, Any], DispatchContext], bool]


META_KEYS = ("seq", "session_id")
ERROR_DOMAIN = "__error__"
ERROR_ALL = "__all__"


# Stable error codes (dispatcher-generated; never extracted from JSON)
ERR_ROOT_EMPTY = "root_empty"
ERR_ROOT_MULTI = "root_multi"
ERR_DOMAIN_EMPTY = "domain_empty"
ERR_DOMAIN_MULTI = "domain_multi"
ERR_UNEXPECTED_VALUE_TYPE = "unexpected_value_type"
ERR_INVALID_SEQ = "invalid_seq"


class Dispatcher:
    """
    Deterministic route extraction + handler fan-out + seq correlation.

    This skeleton intentionally does not implement domain semantics. It only:
    - extracts route
    - classifies broadcast/directed
    - optionally correlates by seq
    - calls registered handlers
    - emits DispatchError notifications
    """

    def __init__(self) -> None:
        self._handlers: Dict[RouteKey, List[DispatchHandler]] = {}
        self._pending: Dict[int, PendingRequest] = {}

    # --- Registration API ---

    def register(self, route: RouteKey, handler: DispatchHandler) -> None:
        """
        Register a handler for a route.

        Reserved:
        - ("__error__", "<error_code>") for dispatch errors
        - ("__error__", "__all__") catch-all errors
        """
        self._handlers.setdefault(route, []).append(handler)

    def register_domain(self, domain: str, handler: DispatchHandler) -> None:
        """
        Convenience: register a domain-level handler for (domain, "__root__").
        This is where ambiguous domain payloads are routed.
        """
        self.register((domain, "__root__"), handler)

    def unregister(self, route: RouteKey, handler: DispatchHandler) -> None:
        handlers = self._handlers.get(route)
        if not handlers:
            return
        try:
            handlers.remove(handler)
        except ValueError:
            return
        if not handlers:
            self._handlers.pop(route, None)

    # --- Pending request API (optional) ---

    def add_pending(self, pending: PendingRequest) -> None:
        self._pending[pending.seq] = pending

    def match_pending(self, seq: int, *, pop: bool = True) -> Optional[PendingRequest]:
        """
        Seq correlation is seq-first. The default policy is one-shot (pop=True).
        """
        if pop:
            return self._pending.pop(seq, None)
        return self._pending.get(seq)

    # --- Dispatch API ---

    def dispatch(self, msg: Mapping[str, Any]) -> DispatchResult:
        """
        Dispatch a single inbound message dict.

        Never raises for unknown/ambiguous routing; returns errors in DispatchResult and emits __error__ handlers.
        Raises TypeError only for programmer error (non-mapping input).
        """
        if not isinstance(msg, Mapping):
            raise TypeError("Dispatcher.dispatch: msg must be a mapping (dict-like JSON object)")

        route, route_errors = self._extract_route(msg)
        seq, kind, seq_errors = self._classify_kind(msg)

        errors: List[DispatchError] = []
        errors.extend(route_errors)
        errors.extend(seq_errors)

        # Correlation / classification
        classification = "UNKNOWN"
        response_match: Optional[PendingRequest] = None
        if kind == MessageKind.BROADCAST:
            classification = "BROADCAST"
        elif kind == MessageKind.DIRECTED and seq is not None:
            pending = self.match_pending(seq, pop=True)
            if pending is not None:
                classification = "RESPONSE"
                response_match = pending
            else:
                classification = "UNSOLICITED"
        else:
            classification = "UNKNOWN"

        session_id = self._get_int(msg, "session_id")

        ctx = DispatchContext(
            kind=kind,
            seq=seq,
            session_id=session_id,
            route=route,
            classification=classification,
            response_match=response_match,
            raw_route=route,
        )

        result = DispatchResult(
            route=route,
            kind=kind,
            seq=seq,
            session_id=session_id,
            classification=classification,
            response_match=response_match,
            errors=errors,
            handled=False,
        )

        # Normal dispatch fan-out
        result.handled = self._dispatch_normal(msg, ctx)

        # Emit dispatch errors (after normal routing)
        if errors:
            self._emit_errors(ctx, errors)

        return result

    # --- Internal: routing + classification ---

    def _extract_route(self, msg: Mapping[str, Any]) -> Tuple[RouteKey, List[DispatchError]]:
        errors: List[DispatchError] = []
        root_non_meta = [k for k in msg.keys() if k not in META_KEYS]

        if len(root_non_meta) == 0:
            errors.append(
                DispatchError(
                    code=ERR_ROOT_EMPTY,
                    message="No domain keys present at root (only meta keys found).",
                    domain="__root__",
                    name="__empty__",
                    keys=tuple(msg.keys()),
                )
            )
            return ("__root__", "__empty__"), errors

        if len(root_non_meta) > 1:
            errors.append(
                DispatchError(
                    code=ERR_ROOT_MULTI,
                    message="Multiple domain keys present at root; cannot determine a single domain.",
                    domain="__root__",
                    name="__multi__",
                    keys=tuple(msg.keys()),  # include meta keys too for full diagnostics
                )
            )
            return ("__root__", "__multi__"), errors

        domain = root_non_meta[0]
        v = msg.get(domain)

        if isinstance(v, Mapping):
            inner_keys = list(v.keys())
            if len(inner_keys) == 0:
                errors.append(
                    DispatchError(
                        code=ERR_DOMAIN_EMPTY,
                        message=f"Domain '{domain}' object is empty; cannot determine message name.",
                        domain=domain,
                        name="__empty__",
                    )
                )
                return (domain, "__empty__"), errors

            if len(inner_keys) == 1:
                # Contract: name is the sole key under the domain object.
                return (domain, inner_keys[0]), errors

            # Multi-key domain object: treat as domain-level payload.
            errors.append(
                DispatchError(
                    code=ERR_DOMAIN_MULTI,
                    message=f"Domain '{domain}' object contains multiple keys; routing to domain-level handler.",
                    domain=domain,
                    name="__root__",
                    keys=tuple(inner_keys),
                )
            )
            return (domain, "__root__"), errors

        errors.append(
            DispatchError(
                code=ERR_UNEXPECTED_VALUE_TYPE,
                message=f"Domain '{domain}' value is unexpected type '{type(v).__name__}'; routing to domain-level handler.",
                domain=domain,
                name="__value__",
            )
        )
        return (domain, "__value__"), errors

    def _classify_kind(self, msg: Mapping[str, Any]) -> Tuple[Optional[int], MessageKind, List[DispatchError]]:
        errors: List[DispatchError] = []

        # Missing seq is allowed and yields UNKNOWN without error (bootstrap/hello often lack root seq).
        if "seq" not in msg:
            return None, MessageKind.UNKNOWN, errors

        seq_val = msg.get("seq")
        if not isinstance(seq_val, int):
            errors.append(
                DispatchError(
                    code=ERR_INVALID_SEQ,
                    message=f"Invalid seq type '{type(seq_val).__name__}' (expected int).",
                    keys=("seq",),
                )
            )
            return None, MessageKind.UNKNOWN, errors

        if seq_val == 0:
            return 0, MessageKind.BROADCAST, errors
        if seq_val > 0:
            return seq_val, MessageKind.DIRECTED, errors

        # Negative or otherwise invalid values: normalize seq to None to simplify downstream.
        errors.append(
            DispatchError(
                code=ERR_INVALID_SEQ,
                message="Invalid seq value (expected 0 for broadcast or >0 for directed).",
                keys=("seq",),
            )
        )
        return None, MessageKind.UNKNOWN, errors

    @staticmethod
    def _get_int(msg: Mapping[str, Any], key: str) -> Optional[int]:
        v = msg.get(key)
        return v if isinstance(v, int) else None

    # --- Internal: handler fan-out ---

    def _dispatch_normal(self, msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        """
        Invoke handlers for:
        - exact route (domain,name)
        - domain-level fallback (domain,"__root__") for ambiguous cases
        Fan-out policy: call all handlers; return indicates "handled" but does not stop others.
        """
        domain, name = ctx.route
        handled = False

        # Exact route
        handled |= self._call_handlers((domain, name), msg, ctx)

        # Domain-level fallback for ambiguous routing; avoid double-dispatch when exact is already __root__.
        if name in ("__empty__", "__value__") and name != "__root__":
            handled |= self._call_handlers((domain, "__root__"), msg, ctx)

        if name == "__root__":
            # __root__ is itself the domain-level route; no additional call needed.
            pass

        # Optional: root diagnostics handlers for "__root__" errors
        if domain == "__root__" and name in ("__empty__", "__multi__"):
            handled |= self._call_handlers(("__root__", "__root__"), msg, ctx)

        return handled

    def _emit_errors(self, ctx: DispatchContext, errors: Iterable[DispatchError]) -> None:
        """
        Emit dispatch errors to:
        - ("__error__", error.code)
        - ("__error__", "__all__")

        Error handlers receive an *error envelope message* that contains the DispatchError details.
        """
        for err in errors:
            err_msg: Mapping[str, Any] = {
                "seq": ctx.seq,
                "session_id": ctx.session_id,
                ERROR_DOMAIN: {
                    err.code: {
                        "message": err.message,
                        "domain": err.domain,
                        "name": err.name,
                        "keys": list(err.keys),
                        "severity": err.severity.value,
                    }
                },
            }

            err_ctx = DispatchContext(
                kind=ctx.kind,
                seq=ctx.seq,
                session_id=ctx.session_id,
                route=(ERROR_DOMAIN, err.code),
                classification=ctx.classification,
                response_match=ctx.response_match,
                raw_route=ctx.raw_route,
            )

            # Specific code
            self._call_handlers((ERROR_DOMAIN, err.code), err_msg, err_ctx)

            # Catch-all
            self._call_handlers((ERROR_DOMAIN, ERROR_ALL), err_msg, err_ctx)

    def _call_handlers(self, route: RouteKey, msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        handlers = self._handlers.get(route)
        if not handlers:
            return False

        handled_any = False
        for h in list(handlers):
            try:
                handled = bool(h(msg, ctx))
            except Exception:
                # Contract: handler exceptions do not break dispatcher.
                handled = False
            handled_any |= handled
        return handled_any
