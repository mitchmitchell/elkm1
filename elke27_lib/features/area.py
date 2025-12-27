"""
elke27_lib/features/area.py

Feature module: area

Converts the existing area handlers into Pattern-1 feature registration:
- Registers inbound handlers for area.get_status / area.set_status / area.__root__
- Registers outbound request builders (read-only sequence of implementation):
    - area.get_status (builder only)
    - (optional later) other area.get_* builders

Notes:
- We are NOT implementing any outbound writes. No set_* builders are registered.
- We DO consume inbound area.set_status messages as ingest-only status updates (Option A).
"""

from __future__ import annotations

from typing import Any, Mapping

from elke27_lib.handlers.area import (
    make_area_domain_fallback_handler,
    make_area_get_status_handler,
    make_area_get_table_info_handler,
    make_area_get_troubles_handler,
    make_area_set_status_handler,
)


ROUTE_AREA_GET_STATUS = ("area", "get_status")
ROUTE_AREA_GET_TABLE_INFO = ("area", "get_table_info")
ROUTE_AREA_GET_TROUBLES = ("area", "get_troubles")
ROUTE_AREA_SET_STATUS = ("area", "set_status")   # inbound-only (no outbound builder)
ROUTE_AREA_ROOT = ("area", "__root__")


def register(elk) -> None:
    # -------------------------
    # Inbound handlers
    # -------------------------
    elk.register_handler(
        ROUTE_AREA_GET_STATUS,
        make_area_get_status_handler(elk.state, elk.emit, elk.now),
    )
    elk.register_handler(
        ROUTE_AREA_GET_TABLE_INFO,
        make_area_get_table_info_handler(elk.state, elk.emit, elk.now),
    )
    elk.register_handler(
        ROUTE_AREA_GET_TROUBLES,
        make_area_get_troubles_handler(elk.state, elk.emit, elk.now),
    )
    elk.register_handler(
        ROUTE_AREA_SET_STATUS,
        make_area_set_status_handler(elk.state, elk.emit, elk.now),
    )
    elk.register_handler(
        ROUTE_AREA_ROOT,
        make_area_domain_fallback_handler(elk.state, elk.emit, elk.now),
    )

    # -------------------------
    # Outbound request builders (GET-only in this phase)
    # -------------------------
    elk.register_request(
        ROUTE_AREA_GET_STATUS,
        build_area_get_status_payload,
    )
    elk.register_request(
        ROUTE_AREA_GET_TABLE_INFO,
        build_area_get_table_info_payload,
    )
    elk.register_request(
        ROUTE_AREA_GET_TROUBLES,
        build_area_get_troubles_payload,
    )


def build_area_get_status_payload(*, area_id: int, **kwargs: Any) -> Mapping[str, Any]:
    # Strict-ish validation here is fine (builders are programmer-facing).
    if not isinstance(area_id, int) or area_id < 1:
        raise ValueError(f"build_area_get_status_payload: area_id must be int >= 1 (got {area_id!r})")
    return {"area_id": area_id}


def build_area_get_troubles_payload(*, area_id: int, **kwargs: Any) -> Mapping[str, Any]:
    if not isinstance(area_id, int) or area_id < 1:
        raise ValueError(f"build_area_get_troubles_payload: area_id must be int >= 1 (got {area_id!r})")
    return {"area_id": area_id}


def build_area_get_table_info_payload(**kwargs: Any) -> Mapping[str, Any]:
    return {}
