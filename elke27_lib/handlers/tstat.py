"""
elke27_lib/handlers/tstat.py

Read/observe-only handlers for the "tstat" domain.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional, Set

from elke27_lib.dispatcher import DispatchContext
from elke27_lib.events import (
    ApiError,
    DispatchRoutingError,
    TstatStatusUpdated,
    TstatTableInfoUpdated,
    UNSET_AT,
    UNSET_CLASSIFICATION,
    UNSET_ROUTE,
    UNSET_SEQ,
    UNSET_SESSION_ID,
)
from elke27_lib.states import PanelState, TstatState


EmitFn = Callable[[object, DispatchContext], None]
NowFn = Callable[[], float]


def make_tstat_get_status_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("tstat","get_status").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        tstat_obj = msg.get("tstat")
        if not isinstance(tstat_obj, Mapping):
            return False

        payload = tstat_obj.get("get_status")
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
                    scope="tstat",
                    entity_id=payload.get("tstat_id") if isinstance(payload.get("tstat_id"), int) else None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        tstat_id = payload.get("tstat_id")
        if not isinstance(tstat_id, int) or tstat_id < 1:
            return False

        tstat = state.get_or_create_tstat(tstat_id)
        changed: Set[str] = set()
        _apply_tstat_status_fields(tstat, payload, changed)
        tstat.last_update_at = now()
        state.panel.last_message_at = tstat.last_update_at

        emit(
            TstatStatusUpdated(
                kind=TstatStatusUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                tstat_id=tstat_id,
                mode=tstat.mode,
                fan_mode=tstat.fan_mode,
                temperature=tstat.temperature,
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_tstat_get_table_info_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("tstat","get_table_info").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        tstat_obj = msg.get("tstat")
        if not isinstance(tstat_obj, Mapping):
            return False

        payload = tstat_obj.get("get_table_info")
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
                    scope="tstat",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        table_info = dict(payload)
        state.table_info_by_domain["tstat"] = table_info
        state.panel.last_message_at = now()

        emit(
            TstatTableInfoUpdated(
                kind=TstatTableInfoUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                domain="tstat",
                table_elements=_extract_int(payload, "table_elements"),
                increment_size=_extract_int(payload, "increment_size"),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def _apply_tstat_status_fields(tstat: TstatState, payload: Mapping[str, Any], changed: Set[str]) -> None:
    _maybe_set(tstat, "temperature", payload.get("temperature"), changed)
    _maybe_set(tstat, "cool_setpoint", payload.get("cool_setpoint"), changed)
    _maybe_set(tstat, "heat_setpoint", payload.get("heat_setpoint"), changed)
    _maybe_set(tstat, "mode", payload.get("mode"), changed)
    _maybe_set(tstat, "fan_mode", payload.get("fan_mode"), changed)
    _maybe_set(tstat, "humidity", payload.get("humidity"), changed)
    _maybe_set(tstat, "rssi", payload.get("rssi"), changed)

    battery = payload.get("battery level")
    if battery is None:
        battery = payload.get("battery_level")
    _maybe_set(tstat, "battery_level", battery, changed)

    prec = payload.get("prec")
    if isinstance(prec, list) and all(isinstance(v, int) for v in prec):
        _maybe_set(tstat, "prec", prec, changed)

    for key, value in payload.items():
        if key in {
            "tstat_id",
            "error_code",
            "temperature",
            "cool_setpoint",
            "heat_setpoint",
            "mode",
            "fan_mode",
            "humidity",
            "rssi",
            "battery level",
            "battery_level",
            "prec",
        }:
            continue
        if tstat.fields.get(key) != value:
            tstat.fields[key] = value
            changed.add(key)


def _maybe_set(tstat: TstatState, attr: str, value: Any, changed: Set[str]) -> None:
    if value is None:
        return
    if getattr(tstat, attr) != value:
        setattr(tstat, attr, value)
        changed.add(attr)


def _extract_int(payload: Mapping[str, Any], key: str) -> Optional[int]:
    value = payload.get(key)
    return value if isinstance(value, int) else None
