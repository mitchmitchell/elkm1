"""
elke27_lib/handlers/ctrl.py

Read-only handlers for the "ctrl" domain.

Colocation policy:
- Message-specific reconcile helpers live in the same module as their handlers.
- Reconcile helpers are module-private (prefixed with _).
- Reconcile helpers are PURE:
    - no dispatcher context
    - no event emission
    - no I/O / logging
- Handlers:
    - extract payload from msg
    - call reconcile helper(s)
    - emit events

Focus: ("ctrl","get_version_info")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Set, Tuple

from elke27_lib.events import (
    ApiError,
    DispatchRoutingError,
    PanelVersionInfoUpdated,
    UNSET_AT,
    UNSET_CLASSIFICATION,
    UNSET_ROUTE,
    UNSET_SEQ,
    UNSET_SESSION_ID,
)
from elke27_lib.states import PanelState
from elke27_lib.dispatcher import DispatchContext  # adjust import to your dispatcher module location


EmitFn = Callable[[object, DispatchContext], None]
NowFn = Callable[[], float]


# -------------------------
# Module-private reconcile
# -------------------------

@dataclass(frozen=True, slots=True)
class _VersionInfoOutcome:
    changed_fields: Tuple[str, ...]
    error_code: Optional[int]
    warnings: Tuple[str, ...]


def _reconcile_ctrl_get_version_info(state: PanelState, payload: Mapping[str, Any], *, now: float) -> _VersionInfoOutcome:
    """
    Pure reconcile for ctrl.get_version_info.

    v0 rules (conservative):
    - Patch-style only (never clears absent fields)
    - Strict typing for stored panel meta fields (strings only)
    - Always updates state.panel.last_message_at
    """
    warnings: list[str] = []
    changed: Set[str] = set()

    # Always update panel freshness
    state.panel.last_message_at = now

    # Optional response field
    error_code = payload.get("error_code")
    if error_code is not None and not isinstance(error_code, int):
        warnings.append(f"field 'error_code' wrong type (expected int, got {type(error_code).__name__})")
        error_code = None

    # Canonical stored fields (expand cautiously once live payload confirms keys)
    # Accept a couple common variants to reduce friction for first live test.
    model = _first_present(payload, ("model", "panel_model", "ctrl_model"))
    firmware = _first_present(payload, ("firmware", "fw", "firmware_version", "sw_version", "SSP"))
    serial = _first_present(payload, ("serial", "serial_number", "sn"))

    if model is not None:
        if isinstance(model, str):
            if state.panel.model != model:
                state.panel.model = model
                changed.add("model")
        else:
            warnings.append(f"field 'model' wrong type (expected str, got {type(model).__name__})")

    if firmware is not None:
        if isinstance(firmware, str):
            if state.panel.firmware != firmware:
                state.panel.firmware = firmware
                changed.add("firmware")
        else:
            warnings.append(f"field 'firmware' wrong type (expected str, got {type(firmware).__name__})")

    if serial is not None:
        if isinstance(serial, str):
            if state.panel.serial != serial:
                state.panel.serial = serial
                changed.add("serial")
        else:
            warnings.append(f"field 'serial' wrong type (expected str, got {type(serial).__name__})")

    return _VersionInfoOutcome(
        changed_fields=tuple(sorted(changed)),
        error_code=error_code,
        warnings=tuple(warnings),
    )


def _first_present(payload: Mapping[str, Any], keys: Tuple[str, ...]) -> Any:
    for k in keys:
        if k in payload:
            return payload.get(k)
    return None


# -------------------------
# Handler factory
# -------------------------

def make_ctrl_get_version_info_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("control","get_version_info") where payload is msg["control"]["get_version_info"].
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        ctrl_obj = msg.get("control")
        if not isinstance(ctrl_obj, Mapping):
            return False

        payload = ctrl_obj.get("get_version_info")
        if not isinstance(payload, Mapping):
            return False

        outcome = _reconcile_ctrl_get_version_info(state, payload, now=now())

        if outcome.changed_fields:
            emit(
                PanelVersionInfoUpdated(
                    kind=PanelVersionInfoUpdated.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    changed_fields=outcome.changed_fields,
                ),
                ctx,
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
                    scope="ctrl",
                    entity_id=None,
                    message=None,
                ),
                ctx,
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
                    message="ctrl.get_version_info payload contained type/schema warnings.",
                    keys=outcome.warnings,
                    severity="info",
                ),
                ctx,
            )

        return True

    return _handler
