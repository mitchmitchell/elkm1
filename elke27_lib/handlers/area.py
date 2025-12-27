"""
elke27_lib/handlers/area.py

Read/observe-only handlers for the "area" domain.

Colocation policy:
- Message-specific reconcile helpers live in the same module as their handlers.
- Reconcile helpers are module-private (prefixed with _).
- Reconcile helpers are PURE:
    - no dispatcher context
    - no event emission
    - no I/O / logging

Policy:
- We do NOT send any writes to the panel in this phase.
- We DO process inbound status messages, including "set_status", as ingest-only updates.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Callable, Mapping, Optional, Set, Tuple, Union

from elke27_lib.events import (
    ApiError,
    AreaStatusUpdated,
    AreaTableInfoUpdated,
    AreaTroublesUpdated,
    DispatchRoutingError,
    UNSET_AT,
    UNSET_CLASSIFICATION,
    UNSET_ROUTE,
    UNSET_SEQ,
    UNSET_SESSION_ID,
    UnknownMessage,
)
from elke27_lib.states import PanelState
from elke27_lib.dispatcher import DispatchContext  # adjust import to your dispatcher module location


EmitFn = Callable[[object, DispatchContext], None]
NowFn = Callable[[], float]

LOG = logging.getLogger(__name__)


# -------------------------
# Module-private reconcile
# -------------------------

@dataclass(frozen=True, slots=True)
class _AreaOutcome:
    area_id: int
    changed_fields: Tuple[str, ...]
    error_code: Optional[int]
    warnings: Tuple[str, ...]


_EXPECTED_TYPES: dict[str, Union[type, Tuple[type, ...]]] = {
    # strings
    "arm_state": str,
    "armed_state": str,
    "alarm_state": str,
    "alarm_event": str,
    "ready_status": str,

    # bools
    "ready": bool,
    "stay": bool,
    "away": bool,
    "bypass": bool,
    "chime": bool,
    "entry_delay_active": bool,
    "exit_delay_active": bool,
    "trouble": bool,

    # ints
    "num_not_ready_zones": int,
    "num_bypassed_zones": int,
    "error_code": int,
}

_FIELD_MAP: dict[str, str] = {
    "arm_state": "arm_state",
    "armed_state": "armed_state",
    "alarm_state": "alarm_state",
    "alarm_event": "alarm_event",

    "ready_status": "ready_status",
    "ready": "ready",
    "stay": "stay",
    "away": "away",
    "bypass": "bypass",
    "chime": "chime",
    "entry_delay_active": "entry_delay_active",
    "exit_delay_active": "exit_delay_active",
    "trouble": "trouble",

    "num_not_ready_zones": "num_not_ready_zones",
    "num_bypassed_zones": "num_bypassed_zones",

    # response field; stored on state as last_error_code
    "error_code": "last_error_code",
}


def _reconcile_area_state(state: PanelState, payload: Mapping[str, Any], *, now: float, source: str) -> _AreaOutcome:
    """
    Pure reconcile for area.* payloads.

    v0 semantics:
    - Requires payload["area_id"] (int >= 1); otherwise returns warnings and no state changes.
    - Patch-style: only fields present in payload are applied; absent fields are not cleared.
    - Strict typing: if a field type mismatches, ignore it and add a warning.
    - Always updates timestamps when area_id is valid:
        - state.panel.last_message_at
        - area.last_update_at
    """
    warnings: list[str] = []
    changed: Set[str] = set()

    area_id_val = payload.get("area_id")
    if not isinstance(area_id_val, int) or area_id_val < 1:
        warnings.append("missing/invalid area_id (expected int >= 1)")
        return _AreaOutcome(
            area_id=-1,
            changed_fields=(),
            error_code=_extract_error_code(payload),
            warnings=tuple(warnings),
        )

    area = state.get_or_create_area(area_id_val)

    for key, attr in _FIELD_MAP.items():
        if key not in payload:
            continue

        value = payload.get(key)
        expected = _EXPECTED_TYPES.get(key)
        if expected is not None and not isinstance(value, expected):
            warnings.append(
                f"field '{key}' wrong type (expected {_type_name(expected)}, got {type(value).__name__})"
            )
            continue

        old = getattr(area, attr)
        if old != value:
            setattr(area, attr, value)
            changed.add(attr)

    # timestamps (monotonic)
    area.last_update_at = now
    state.panel.last_message_at = now

    return _AreaOutcome(
        area_id=area_id_val,
        changed_fields=tuple(sorted(changed)),
        error_code=_extract_error_code(payload),
        warnings=tuple(warnings),
    )


def _extract_error_code(payload: Mapping[str, Any]) -> Optional[int]:
    v = payload.get("error_code")
    return v if isinstance(v, int) else None


def _type_name(t: Union[type, Tuple[type, ...]]) -> str:
    if isinstance(t, tuple):
        return " | ".join(x.__name__ for x in t)
    return t.__name__


# -------------------------
# Handler factories
# -------------------------

def make_area_get_status_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("area","get_status") where payload is msg["area"]["get_status"].
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        area_obj = msg.get("area")
        if not isinstance(area_obj, Mapping):
            return False

        payload = area_obj.get("get_status")
        if not isinstance(payload, Mapping):
            return False

        error_code = _extract_error_code(payload)
        if error_code is not None and error_code != 0:
            area_id = payload.get("area_id")
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=error_code,
                    scope="area",
                    entity_id=area_id if isinstance(area_id, int) else None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        outcome = _reconcile_area_state(state, payload, now=now(), source="snapshot")
        if state.debug_last_raw_by_route_enabled:
            state.debug_last_raw_by_route["area.get_status"] = dict(payload)

        if outcome.area_id < 1:
            emit(
                DispatchRoutingError(
                    kind=DispatchRoutingError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    code="schema_invalid_area_id",
                    message="area.get_status missing/invalid area_id; ignoring payload.",
                    keys=tuple(payload.keys()),
                    severity="warning",
                ),
                ctx=ctx,
            )
            return False

        if outcome.changed_fields:
            LOG.debug("area.get_status changed_fields=%s area_id=%s", outcome.changed_fields, outcome.area_id)
            evt = AreaStatusUpdated(
                kind=AreaStatusUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                area_id=outcome.area_id,
                changed_fields=outcome.changed_fields,
            )
            try:
                emit(evt, ctx=ctx)
                LOG.debug("area.get_status emitted AreaStatusUpdated")
            except Exception as e:
                LOG.error("area.get_status emit failed: %s", e, exc_info=True)

        if outcome.warnings:
            emit(
                DispatchRoutingError(
                    kind=DispatchRoutingError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    code="schema_warnings",
                    message="area.get_status payload contained type/schema warnings.",
                    keys=outcome.warnings,
                    severity="info",
                ),
                ctx=ctx,
            )

        return True

    return _handler


def make_area_set_status_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("area","set_status") ingest-only status reconcile.
    Even though the name implies a write, in this phase we do not send writes;
    we simply consume inbound messages of this name if they appear.
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        area_obj = msg.get("area")
        if not isinstance(area_obj, Mapping):
            return False

        payload = area_obj.get("set_status")
        if not isinstance(payload, Mapping):
            return False

        outcome = _reconcile_area_state(state, payload, now=now(), source="delta")

        if outcome.area_id < 1:
            emit(
                DispatchRoutingError(
                    kind=DispatchRoutingError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    code="schema_invalid_area_id",
                    message="area.set_status missing/invalid area_id; ignoring payload.",
                    keys=tuple(payload.keys()),
                    severity="warning",
                ),
                ctx=ctx,
            )
            return False

        if outcome.changed_fields:
            emit(
                AreaStatusUpdated(
                    kind=AreaStatusUpdated.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    area_id=outcome.area_id,
                    changed_fields=outcome.changed_fields,
                ),
                ctx=ctx,
            )

        if outcome.error_code is not None and outcome.error_code != 0:
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=outcome.error_code,
                    scope="area",
                    entity_id=outcome.area_id,
                    message=None,
                ),
                ctx=ctx,
            )

        if outcome.warnings:
            emit(
                DispatchRoutingError(
                    kind=DispatchRoutingError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    code="schema_warnings",
                    message="area.set_status payload contained type/schema warnings.",
                    keys=outcome.warnings,
                    severity="info",
                ),
                ctx=ctx,
            )

        return True

    return _handler


def make_area_get_troubles_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("area","get_troubles").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        area_obj = msg.get("area")
        if not isinstance(area_obj, Mapping):
            return False

        payload = area_obj.get("get_troubles")
        if not isinstance(payload, Mapping):
            return False

        error_code = _extract_error_code(payload)
        if error_code is not None and error_code != 0:
            area_id = payload.get("area_id")
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=error_code,
                    scope="area",
                    entity_id=area_id if isinstance(area_id, int) else None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        area_id = payload.get("area_id")
        if not isinstance(area_id, int) or area_id < 1:
            return False

        troubles = _extract_troubles_list(payload)
        area = state.get_or_create_area(area_id)
        area.troubles = troubles
        area.last_update_at = now()
        state.panel.last_message_at = area.last_update_at

        emit(
            AreaTroublesUpdated(
                kind=AreaTroublesUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                area_id=area_id,
                troubles=tuple(troubles or []),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_area_get_table_info_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("area","get_table_info").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        area_obj = msg.get("area")
        if not isinstance(area_obj, Mapping):
            return False

        payload = area_obj.get("get_table_info")
        if not isinstance(payload, Mapping):
            return False

        error_code = _extract_error_code(payload)
        if error_code is not None and error_code != 0:
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=error_code,
                    scope="area",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        table_info = dict(payload)
        state.table_info_by_domain["area"] = table_info
        state.panel.last_message_at = now()

        emit(
            AreaTableInfoUpdated(
                kind=AreaTableInfoUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                domain="area",
                table_elements=_extract_int(payload, "table_elements"),
                increment_size=_extract_int(payload, "increment_size"),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_area_domain_fallback_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("area","__root__") to catch multi-key/ambiguous area payloads.
    This is intentionally conservative: it does not attempt to interpret unknown shapes.
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        area_obj = msg.get("area")
        if not isinstance(area_obj, Mapping):
            return False

        if state.debug_last_raw_by_route_enabled:
            state.debug_last_raw_by_route["area.__root__"] = dict(area_obj)

        emit(
            UnknownMessage(
                kind=UnknownMessage.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                unhandled_route=("area", "__root__"),
                keys=tuple(area_obj.keys()),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def _extract_troubles_list(payload: Mapping[str, Any]) -> list[str]:
    for key in ("troubles", "trouble", "items", "list"):
        if key in payload:
            value = payload.get(key)
            if isinstance(value, list):
                return [str(v) for v in value if v is not None]
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    return []
                return [text]
    return []


def _extract_int(payload: Mapping[str, Any], key: str) -> Optional[int]:
    value = payload.get(key)
    return value if isinstance(value, int) else None
