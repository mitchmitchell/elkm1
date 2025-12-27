"""
elke27_lib/handlers/output.py

Read/observe-only handlers for the "output" domain.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional, Set

from elke27_lib.dispatcher import DispatchContext
from elke27_lib.events import (
    ApiError,
    DispatchRoutingError,
    OutputStatusUpdated,
    OutputTableInfoUpdated,
    OutputsStatusBulkUpdated,
    UNSET_AT,
    UNSET_CLASSIFICATION,
    UNSET_ROUTE,
    UNSET_SEQ,
    UNSET_SESSION_ID,
)
from elke27_lib.states import OutputState, PanelState


EmitFn = Callable[[object, DispatchContext], None]
NowFn = Callable[[], float]


def make_output_get_status_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("output","get_status").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        output_obj = msg.get("output")
        if not isinstance(output_obj, Mapping):
            return False

        payload = output_obj.get("get_status")
        if not isinstance(payload, Mapping):
            return False

        error_code = payload.get("error_code")
        if isinstance(error_code, int) and error_code != 0:
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=error_code,
                    scope="output",
                    entity_id=payload.get("output_id") if isinstance(payload.get("output_id"), int) else None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        output_id = payload.get("output_id")
        if not isinstance(output_id, int) or output_id < 1:
            return False

        output = state.get_or_create_output(output_id)
        changed: Set[str] = set()
        _apply_output_status_fields(output, payload, changed)
        output.last_update_at = now()
        state.panel.last_message_at = output.last_update_at

        emit(
            OutputStatusUpdated(
                kind=OutputStatusUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                output_id=output_id,
                status=output.status,
                on=output.on,
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_output_get_all_outputs_status_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("output","get_all_outputs_status").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        output_obj = msg.get("output")
        if not isinstance(output_obj, Mapping):
            return False

        payload = output_obj.get("get_all_outputs_status")
        if not isinstance(payload, Mapping):
            return False

        error_code = payload.get("error_code")
        if isinstance(error_code, int) and error_code != 0:
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=error_code,
                    scope="output",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        status_text = payload.get("status")
        if not isinstance(status_text, str):
            emit(
                DispatchRoutingError(
                    kind=DispatchRoutingError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    code="schema_warnings",
                    message="output.get_all_outputs_status missing status string.",
                    keys=tuple(payload.keys()),
                    severity="info",
                ),
                ctx=ctx,
            )
            return True

        compact = "".join(status_text.split()).upper()
        updated: list[int] = []
        for idx, ch in enumerate(compact):
            output_id = idx + 1
            output = state.get_or_create_output(output_id)
            if _apply_output_status_char(output, ch):
                output.last_update_at = now()
                updated.append(output_id)

        if updated:
            state.panel.last_message_at = now()

        emit(
            OutputsStatusBulkUpdated(
                kind=OutputsStatusBulkUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                updated_count=len(updated),
                updated_ids=tuple(updated),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_output_get_table_info_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("output","get_table_info").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        output_obj = msg.get("output")
        if not isinstance(output_obj, Mapping):
            return False

        payload = output_obj.get("get_table_info")
        if not isinstance(payload, Mapping):
            return False

        error_code = payload.get("error_code")
        if isinstance(error_code, int) and error_code != 0:
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=error_code,
                    scope="output",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        table_info = dict(payload)
        state.table_info_by_domain["output"] = table_info
        state.panel.last_message_at = now()

        emit(
            OutputTableInfoUpdated(
                kind=OutputTableInfoUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                domain="output",
                table_elements=_extract_int(payload, "table_elements"),
                increment_size=_extract_int(payload, "increment_size"),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def _apply_output_status_fields(output: OutputState, payload: Mapping[str, Any], changed: Set[str]) -> None:
    status = payload.get("status")
    if isinstance(status, str):
        norm = status.strip().upper()
        if output.status != norm:
            output.status = norm
            changed.add("status")
        on = norm == "ON"
        if output.on != on:
            output.on = on
            changed.add("on")

    for key, value in payload.items():
        if key in {"output_id", "error_code", "status"}:
            continue
        if output.fields.get(key) != value:
            output.fields[key] = value
            changed.add(key)


def _apply_output_status_char(output: OutputState, ch: str) -> bool:
    if ch not in {"0", "1"}:
        return False
    output.status_code = ch
    output.on = ch == "1"
    output.status = "ON" if output.on else "OFF"
    return True


def _extract_int(payload: Mapping[str, Any], key: str) -> Optional[int]:
    value = payload.get(key)
    return value if isinstance(value, int) else None
