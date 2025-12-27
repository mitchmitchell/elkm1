"""
elke27_lib/handlers/zone.py

Read/observe-only handlers for the "zone" domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence, Set, Tuple

from elke27_lib.dispatcher import DispatchContext
from elke27_lib.events import (
    ApiError,
    DispatchRoutingError,
    UNSET_AT,
    UNSET_CLASSIFICATION,
    UNSET_ROUTE,
    UNSET_SEQ,
    UNSET_SESSION_ID,
    ZoneDefFlagsUpdated,
    ZoneDefsUpdated,
    ZoneAttribsUpdated,
    ZoneConfiguredUpdated,
    ZoneTableInfoUpdated,
    ZonesStatusBulkUpdated,
)
from elke27_lib.states import PanelState, ZoneState


EmitFn = Callable[[object, DispatchContext], None]
NowFn = Callable[[], float]


@dataclass(frozen=True, slots=True)
class _ConfiguredOutcome:
    configured_ids: Tuple[int, ...]
    warnings: Tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _BulkStatusOutcome:
    updated_ids: Tuple[int, ...]
    warnings: Tuple[str, ...]


_ZONE_STATUS_FIELDS: dict[str, str] = {
    "name": "name",
    "area_id": "area_id",
    "enabled": "enabled",
    "bypassed": "bypassed",
    "violated": "violated",
    "trouble": "trouble",
    "tamper": "tamper",
    "alarm": "alarm",
}

_ZONE_STATUS_TYPES: dict[str, type] = {
    "name": str,
    "area_id": int,
    "enabled": bool,
    "bypassed": bool,
    "violated": bool,
    "trouble": bool,
    "tamper": bool,
    "alarm": bool,
}


def make_zone_get_configured_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("zone","get_configured").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        zone_obj = msg.get("zone")
        if not isinstance(zone_obj, Mapping):
            return False

        payload = zone_obj.get("get_configured")
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
                    scope="zone",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        outcome = _reconcile_configured_zones(state, payload, now=now())
        if outcome.configured_ids:
            emit(
                ZoneConfiguredUpdated(
                    kind=ZoneConfiguredUpdated.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    configured_ids=outcome.configured_ids,
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
                    message="zone.get_configured payload contained type/schema warnings.",
                    keys=outcome.warnings,
                    severity="info",
                ),
                ctx=ctx,
            )

        return True

    return _handler


def make_zone_get_attribs_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("zone","get_attribs").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        zone_obj = msg.get("zone")
        if not isinstance(zone_obj, Mapping):
            return False

        payload = zone_obj.get("get_attribs")
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
                    scope="zone",
                    entity_id=payload.get("zone_id") if isinstance(payload.get("zone_id"), int) else None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        zone_id = payload.get("zone_id")
        if not isinstance(zone_id, int) or zone_id < 1:
            return False

        zone = state.get_or_create_zone(zone_id)
        changed: Set[str] = set()
        _apply_zone_attribs(zone, payload, changed)
        zone.last_update_at = now()
        state.panel.last_message_at = zone.last_update_at

        if changed:
            emit(
                ZoneAttribsUpdated(
                    kind=ZoneAttribsUpdated.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    zone_id=zone_id,
                    changed_fields=tuple(sorted(changed)),
                ),
                ctx=ctx,
            )

        return True

    return _handler


def make_zone_get_all_zones_status_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("zone","get_all_zones_status").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        zone_obj = msg.get("zone")
        if not isinstance(zone_obj, Mapping):
            return False

        payload = zone_obj.get("get_all_zones_status")
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
                    scope="zone",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        outcome = _reconcile_bulk_zone_status(state, payload, now=now())
        if outcome.updated_ids:
            emit(
                ZonesStatusBulkUpdated(
                    kind=ZonesStatusBulkUpdated.KIND,
                    at=UNSET_AT,
                    seq=UNSET_SEQ,
                    classification=UNSET_CLASSIFICATION,
                    route=UNSET_ROUTE,
                    session_id=UNSET_SESSION_ID,
                    updated_count=len(outcome.updated_ids),
                    updated_ids=outcome.updated_ids,
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
                    message="zone.get_all_zones_status payload contained type/schema warnings.",
                    keys=outcome.warnings,
                    severity="info",
                ),
                ctx=ctx,
            )

        return True

    return _handler


def make_zone_get_table_info_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("zone","get_table_info").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        zone_obj = msg.get("zone")
        if not isinstance(zone_obj, Mapping):
            return False

        payload = zone_obj.get("get_table_info")
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
                    scope="zone",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        table_info = dict(payload)
        state.table_info_by_domain["zone"] = table_info
        state.panel.last_message_at = now()

        emit(
            ZoneTableInfoUpdated(
                kind=ZoneTableInfoUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                domain="zone",
                table_elements=_extract_int(payload, "table_elements"),
                increment_size=_extract_int(payload, "increment_size"),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_zone_get_defs_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("zone","get_defs").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        zone_obj = msg.get("zone")
        if not isinstance(zone_obj, Mapping):
            return False

        payload = zone_obj.get("get_defs")
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
                    scope="zone",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        defs = payload.get("definitions")
        if not isinstance(defs, list):
            return False

        block_id = payload.get("block_id")
        if isinstance(block_id, int) and block_id >= 1 and defs:
            # Preserve API meaning: block_id is 1-based; offset by block size we observed.
            base_index = 1 + (block_id - 1) * len(defs)
        else:
            base_index = 1

        updated: list[int] = []
        for idx, name in enumerate(defs):
            if name is None:
                continue
            def_id = base_index + idx
            state.zone_defs_by_id[def_id] = {"definition": str(name)}
            updated.append(def_id)

        if updated:
            state.panel.last_message_at = now()

        emit(
            ZoneDefsUpdated(
                kind=ZoneDefsUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                count=len(updated),
                updated_ids=tuple(updated),
            ),
            ctx=ctx,
        )
        return True

    return _handler


def make_zone_get_def_flags_handler(state: PanelState, emit: EmitFn, now: NowFn):
    """
    Handler for ("zone","get_def_flags").
    """
    def _handler(msg: Mapping[str, Any], ctx: DispatchContext) -> bool:
        zone_obj = msg.get("zone")
        if not isinstance(zone_obj, Mapping):
            return False

        payload = zone_obj.get("get_def_flags")
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
                    scope="zone",
                    entity_id=None,
                    message=None,
                ),
                ctx=ctx,
            )
            return True

        definition = payload.get("definition")
        flags = payload.get("flags")
        if definition is None or flags is None:
            return False

        entry = {"definition": str(definition), "flags": flags}
        state.zone_def_flags_by_name[str(definition)] = entry

        def_id = _resolve_zone_def_id(state, str(definition))
        if def_id is not None:
            state.zone_def_flags_by_id[def_id] = entry

        state.panel.last_message_at = now()

        emit(
            ZoneDefFlagsUpdated(
                kind=ZoneDefFlagsUpdated.KIND,
                at=UNSET_AT,
                seq=UNSET_SEQ,
                classification=UNSET_CLASSIFICATION,
                route=UNSET_ROUTE,
                session_id=UNSET_SESSION_ID,
                count=1,
            ),
            ctx=ctx,
        )
        return True

    return _handler


def _reconcile_configured_zones(state: PanelState, payload: Mapping[str, Any], *, now: float) -> _ConfiguredOutcome:
    warnings: list[str] = []
    ids = _extract_configured_zone_ids(payload, warnings)
    if ids:
        block_id = payload.get("block_id")
        if isinstance(block_id, int) and block_id == 1:
            state.configured_zone_ids = set()
        state.configured_zone_ids.update(ids)
        state.panel.last_message_at = now
        for zone_id in ids:
            zone = state.get_or_create_zone(zone_id)
            zone.last_update_at = now
    return _ConfiguredOutcome(configured_ids=tuple(ids), warnings=tuple(warnings))


def _extract_configured_zone_ids(payload: Mapping[str, Any], warnings: list[str]) -> list[int]:
    candidates: list[Any] = []

    for key in ("configured_zone_ids", "configured_zones", "zone_ids", "zones", "configured"):
        if key in payload:
            candidates.append(payload.get(key))

    for key in ("bitmask", "bitmap", "mask", "zone_mask"):
        if key in payload:
            candidates.append(payload.get(key))

    for value in candidates:
        ids = _parse_zone_id_container(value, warnings)
        if ids:
            return ids

    warnings.append("no configured zone ids found")
    return []


def _parse_zone_id_container(value: Any, warnings: list[str]) -> list[int]:
    if value is None:
        return []

    if isinstance(value, list):
        ids: list[int] = []
        for item in value:
            zone_id = _coerce_zone_id(item)
            if zone_id is not None:
                ids.append(zone_id)
        return _dedupe_sorted(ids)

    if isinstance(value, dict):
        ids: list[int] = []
        for k, v in value.items():
            zone_id = _coerce_zone_id(k)
            if zone_id is not None:
                if isinstance(v, bool) and not v:
                    continue
                ids.append(zone_id)
            elif isinstance(v, Mapping):
                zone_id = _coerce_zone_id(v.get("zone_id") or v.get("id"))
                if zone_id is not None:
                    ids.append(zone_id)
        return _dedupe_sorted(ids)

    if isinstance(value, int):
        return _ids_from_bitmask(value)

    if isinstance(value, str):
        text = value.strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        try:
            mask = int(text, 16)
        except ValueError:
            warnings.append(f"configured ids string not hex: {value!r}")
            return []
        return _ids_from_bitmask(mask)

    warnings.append(f"unsupported configured zone ids type: {type(value).__name__}")
    return []


def _ids_from_bitmask(mask: int) -> list[int]:
    ids: list[int] = []
    bit = 1
    zone_id = 1
    while bit <= mask:
        if mask & bit:
            ids.append(zone_id)
        bit <<= 1
        zone_id += 1
    return ids


def _reconcile_bulk_zone_status(state: PanelState, payload: Mapping[str, Any], *, now: float) -> _BulkStatusOutcome:
    warnings: list[str] = []
    status_text = payload.get("status")
    if isinstance(status_text, str):
        updated: list[int] = []
        compact = "".join(status_text.split()).upper()
        for idx, ch in enumerate(compact):
            zone_id = idx + 1
            zone = state.get_or_create_zone(zone_id)
            if _apply_zone_status_char(zone, ch, warnings):
                zone.last_update_at = now
                updated.append(zone_id)
        if updated:
            state.panel.last_message_at = now
        return _BulkStatusOutcome(updated_ids=tuple(_dedupe_sorted(updated)), warnings=tuple(warnings))

    items = _extract_zone_status_items(payload, warnings)
    updated: list[int] = []

    if not items:
        warnings.append("no zone status items found")
        return _BulkStatusOutcome(updated_ids=(), warnings=tuple(warnings))

    for item in items:
        zone_id = _coerce_zone_id(item.get("zone_id") or item.get("id") or item.get("zone"))
        if zone_id is None:
            warnings.append("zone status item missing zone_id")
            continue

        zone = state.get_or_create_zone(zone_id)
        _apply_zone_fields(zone, item, warnings)
        zone.last_update_at = now
        updated.append(zone_id)

    if updated:
        state.panel.last_message_at = now

    return _BulkStatusOutcome(updated_ids=tuple(_dedupe_sorted(updated)), warnings=tuple(warnings))


def _apply_zone_status_char(zone: ZoneState, ch: str, warnings: list[str]) -> bool:
    disabled = {"0", "4", "8", "C"}
    normal = {"1", "2", "3"}
    trouble = {"5", "6", "7"}
    violated = {"9", "A", "B"}
    bypassed = {"D", "E", "F"}

    if ch not in disabled | normal | trouble | violated | bypassed:
        warnings.append(f"unknown zone status char: {ch!r}")
        return False

    zone.status_code = ch
    if ch in disabled:
        zone.enabled = False
        zone.trouble = False
        zone.violated = False
        zone.bypassed = False
    elif ch in normal:
        zone.enabled = True
        zone.trouble = False
        zone.violated = False
        zone.bypassed = False
    elif ch in trouble:
        zone.enabled = True
        zone.trouble = True
        zone.violated = False
        zone.bypassed = False
    elif ch in violated:
        zone.enabled = True
        zone.trouble = False
        zone.violated = True
        zone.bypassed = False
    else:
        zone.enabled = True
        zone.trouble = False
        zone.violated = False
        zone.bypassed = True
    return True


def _extract_zone_status_items(payload: Mapping[str, Any], warnings: list[str]) -> list[Mapping[str, Any]]:
    for key in ("zones", "zone_statuses", "zone_status", "status"):
        if key in payload:
            value = payload.get(key)
            items = _coerce_zone_items(value, warnings)
            if items:
                return items
    return []


def _coerce_zone_items(value: Any, warnings: list[str]) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, Mapping)]
    if isinstance(value, dict):
        # If values are mappings, treat them as items; else treat dict as a single item.
        if all(isinstance(v, Mapping) for v in value.values()):
            return [v for v in value.values() if isinstance(v, Mapping)]
        return [value]
    warnings.append(f"unsupported zone status container type: {type(value).__name__}")
    return []


def _apply_zone_fields(zone: ZoneState, item: Mapping[str, Any], warnings: list[str]) -> None:
    for key, attr in _ZONE_STATUS_FIELDS.items():
        if key not in item:
            continue
        value = item.get(key)
        expected = _ZONE_STATUS_TYPES.get(key)
        if expected is not None and not isinstance(value, expected):
            warnings.append(
                f"field '{key}' wrong type (expected {expected.__name__}, got {type(value).__name__})"
            )
            continue
        setattr(zone, attr, value)


def _apply_zone_attribs(zone: ZoneState, payload: Mapping[str, Any], changed: Set[str]) -> None:
    for key, attr in (("name", "name"), ("area_id", "area_id"), ("definition", "definition"), ("flags", "flags")):
        if key in payload:
            value = payload.get(key)
            if getattr(zone, attr) != value:
                setattr(zone, attr, value)
                changed.add(attr)

    for key, value in payload.items():
        if key in {"zone_id", "error_code", "name", "area_id", "definition", "flags"}:
            continue
        if zone.attribs.get(key) != value:
            zone.attribs[key] = value
            changed.add(key)


def _coerce_zone_id(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, str):
        try:
            num = int(value)
        except ValueError:
            return None
        return num if num >= 1 else None
    if isinstance(value, Mapping):
        inner = value.get("zone_id") or value.get("id")
        return _coerce_zone_id(inner)
    return None


def _dedupe_sorted(ids: Iterable[int]) -> list[int]:
    return sorted({i for i in ids if i >= 1})


def _extract_int(payload: Mapping[str, Any], key: str) -> Optional[int]:
    value = payload.get(key)
    return value if isinstance(value, int) else None


def _resolve_zone_def_id(state: PanelState, definition: str) -> Optional[int]:
    for def_id, entry in state.zone_defs_by_id.items():
        if entry.get("definition") == definition:
            return def_id
    return None
