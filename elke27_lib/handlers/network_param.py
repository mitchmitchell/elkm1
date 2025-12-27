"""
elke27_lib/handlers/network_param.py

Read/observe-only handlers for the "network" domain.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from elke27_lib.dispatcher import DispatchContext
from elke27_lib.events import (
    ApiError,
    NetworkRssiUpdated,
    NetworkSsidResultsUpdated,
    UNSET_AT,
    UNSET_CLASSIFICATION,
    UNSET_ROUTE,
    UNSET_SEQ,
    UNSET_SESSION_ID,
)
from elke27_lib.states import NetworkState, PanelState


EmitFn = Callable[[object, DispatchContext], None]
NowFn = Callable[[], float]


def make_network_get_ssid_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("network","get_ssid").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        net_obj = msg.get("network")
        if not isinstance(net_obj, Mapping):
            return False

        error_code = net_obj.get("error_code")
        payload = net_obj.get("get_ssid")
        if isinstance(payload, Mapping):
            error_code = payload.get("error_code", error_code)

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
                    scope="network",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        results = _normalize_ssid_results(payload, net_obj)
        state.network.ssid_scan_results = results
        state.network.last_update_at = now()
        state.panel.last_message_at = state.network.last_update_at

        emit(
            NetworkSsidResultsUpdated(
                kind=NetworkSsidResultsUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                count=len(results),
                ssids=tuple(r.get("ssid", "") for r in results if isinstance(r.get("ssid"), str)),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_network_get_rssi_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("network","get_rssi").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        net_obj = msg.get("network")
        if not isinstance(net_obj, Mapping):
            return False

        payload = net_obj.get("get_rssi")
        if payload is not None and not isinstance(payload, Mapping):
            return False

        error_code = net_obj.get("error_code")
        if isinstance(payload, Mapping):
            error_code = payload.get("error_code", error_code)

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
                    scope="network",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        rssi = _extract_rssi(payload, net_obj)
        state.network.rssi = rssi
        state.network.last_update_at = now()
        state.panel.last_message_at = state.network.last_update_at

        emit(
            NetworkRssiUpdated(
                kind=NetworkRssiUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                rssi=rssi,
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_network_error_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("network","error") domain-root errors.
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        net_obj = msg.get("network")
        if not isinstance(net_obj, Mapping):
            return False

        error_code = net_obj.get("error_code")
        if isinstance(error_code, str):
            try:
                error_code = int(error_code)
            except ValueError:
                error_code = None

        if isinstance(error_code, int):
            emit(
                ApiError(
                    kind=ApiError.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    error_code=error_code,
                    scope="network",
                    entity_id=None,
                    message=net_obj.get("error_message"),
                ),
                ctx=ctx,
            )
            return True

        return False

    return _handler


def _normalize_ssid_results(payload: Any, net_obj: Mapping[str, Any]) -> list[dict]:
    if payload is None:
        return []

    if isinstance(payload, list):
        return [_normalize_ssid_entry(item) for item in payload if _normalize_ssid_entry(item) is not None]

    if isinstance(payload, str):
        return [{"ssid": payload}]

    if isinstance(payload, Mapping):
        for key in ("ssids", "results", "list", "scan"):
            if key in payload and isinstance(payload.get(key), list):
                return [
                    _normalize_ssid_entry(item)
                    for item in payload.get(key, [])
                    if _normalize_ssid_entry(item) is not None
                ]
        if "ssid" in payload:
            return [{"ssid": str(payload.get("ssid"))}]
        return [dict(payload)]

    if isinstance(net_obj.get("get_ssid"), list):
        return [_normalize_ssid_entry(item) for item in net_obj.get("get_ssid") if _normalize_ssid_entry(item)]

    return []


def _normalize_ssid_entry(item: Any) -> Optional[dict]:
    if isinstance(item, Mapping):
        return dict(item)
    if isinstance(item, str):
        return {"ssid": item}
    return None


def _extract_rssi(payload: Optional[Mapping[str, Any]], net_obj: Mapping[str, Any]) -> Optional[int]:
    if isinstance(payload, Mapping):
        value = payload.get("rssi")
    else:
        value = net_obj.get("rssi")

    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
