"""
elke27_lib/events.py

Event dataclasses v0 (clean model).

Rules:
- Handlers construct event objects directly, with placeholder header fields.
- Elk.emit() stamps the authoritative header fields from DispatchContext and enqueues.
- No payload helper functions (cleanest possible API surface).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional, Tuple


RouteKey = Tuple[str, str]


# -------------------------
# Common header (stamped by Elk.emit)
# -------------------------

@dataclass(frozen=True, slots=True)
class Event:
    # Common header fields (Elk.emit overwrites these unconditionally)
    kind: str
    at: float
    seq: Optional[int]
    classification: str
    route: RouteKey
    session_id: Optional[int]


# Placeholder header values for handlers (optional convenience constants)
UNSET_ROUTE: RouteKey = ("__unset__", "__unset__")
UNSET_AT: float = 0.0
UNSET_SEQ: Optional[int] = None
UNSET_CLASSIFICATION: str = "UNKNOWN"
UNSET_SESSION_ID: Optional[int] = None


# -------------------------
# Connection lifecycle
# -------------------------

@dataclass(frozen=True, slots=True)
class ConnectionStateChanged(Event):
    KIND = "connection_state_changed"

    connected: bool
    reason: Optional[str] = None
    error_type: Optional[str] = None


# -------------------------
# Area events
# -------------------------

@dataclass(frozen=True, slots=True)
class AreaStatusUpdated(Event):
    KIND = "area_status_updated"

    area_id: int
    changed_fields: Tuple[str, ...]  # sorted tuple for deterministic tests/logs


# -------------------------
# Zone events
# -------------------------

@dataclass(frozen=True, slots=True)
class ZoneConfiguredUpdated(Event):
    KIND = "zone_configured_updated"

    configured_ids: Tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ZonesStatusBulkUpdated(Event):
    KIND = "zones_status_bulk_updated"

    updated_count: int
    updated_ids: Tuple[int, ...]


# -------------------------
# Zone definitions
# -------------------------

@dataclass(frozen=True, slots=True)
class ZoneDefsUpdated(Event):
    KIND = "zone_defs_updated"

    count: int
    updated_ids: Tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ZoneDefFlagsUpdated(Event):
    KIND = "zone_def_flags_updated"

    count: int


# -------------------------
# Zone attribs
# -------------------------

@dataclass(frozen=True, slots=True)
class ZoneAttribsUpdated(Event):
    KIND = "zone_attribs_updated"

    zone_id: int
    changed_fields: Tuple[str, ...]


# -------------------------
# Area troubles
# -------------------------

@dataclass(frozen=True, slots=True)
class AreaTroublesUpdated(Event):
    KIND = "area_troubles_updated"

    area_id: Optional[int]
    troubles: Tuple[str, ...]


# -------------------------
# Output events
# -------------------------

@dataclass(frozen=True, slots=True)
class OutputStatusUpdated(Event):
    KIND = "output_status_updated"

    output_id: int
    status: Optional[str]
    on: Optional[bool]


@dataclass(frozen=True, slots=True)
class OutputsStatusBulkUpdated(Event):
    KIND = "outputs_status_bulk_updated"

    updated_count: int
    updated_ids: Tuple[int, ...]


# -------------------------
# Tstat events
# -------------------------

@dataclass(frozen=True, slots=True)
class TstatStatusUpdated(Event):
    KIND = "tstat_status_updated"

    tstat_id: int
    mode: Optional[str]
    fan_mode: Optional[str]
    temperature: Optional[int]


# -------------------------
# Network events
# -------------------------

@dataclass(frozen=True, slots=True)
class NetworkSsidResultsUpdated(Event):
    KIND = "network_ssid_results_updated"

    count: int
    ssids: Tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NetworkRssiUpdated(Event):
    KIND = "network_rssi_updated"

    rssi: Optional[int]


# -------------------------
# Table info events
# -------------------------

@dataclass(frozen=True, slots=True)
class AreaTableInfoUpdated(Event):
    KIND = "area_table_info_updated"

    domain: str
    table_elements: Optional[int]
    increment_size: Optional[int]


@dataclass(frozen=True, slots=True)
class ZoneTableInfoUpdated(Event):
    KIND = "zone_table_info_updated"

    domain: str
    table_elements: Optional[int]
    increment_size: Optional[int]


@dataclass(frozen=True, slots=True)
class OutputTableInfoUpdated(Event):
    KIND = "output_table_info_updated"

    domain: str
    table_elements: Optional[int]
    increment_size: Optional[int]


@dataclass(frozen=True, slots=True)
class TstatTableInfoUpdated(Event):
    KIND = "tstat_table_info_updated"

    domain: str
    table_elements: Optional[int]
    increment_size: Optional[int]


# -------------------------
# Trouble / diagnostics
# -------------------------

@dataclass(frozen=True, slots=True)
class TroubleStatusUpdated(Event):
    KIND = "trouble_status_updated"

    active: Optional[bool]
    changed_fields: Tuple[str, ...]


# -------------------------
# Panel version info
# -------------------------

@dataclass(frozen=True, slots=True)
class PanelVersionInfoUpdated(Event):
    KIND = "panel_version_info_updated"

    changed_fields: Tuple[str, ...]


# -------------------------
# API / protocol errors
# -------------------------

@dataclass(frozen=True, slots=True)
class ApiError(Event):
    KIND = "api_error"

    error_code: int
    scope: Optional[str] = None
    entity_id: Optional[int] = None
    message: Optional[str] = None


@dataclass(frozen=True, slots=True)
class DispatchRoutingError(Event):
    KIND = "dispatch_routing_error"

    code: str
    message: str
    keys: Tuple[str, ...]
    severity: str  # "debug"|"info"|"warning"|"error"


# -------------------------
# Unknown/unhandled
# -------------------------

@dataclass(frozen=True, slots=True)
class UnknownMessage(Event):
    KIND = "unknown_message"

    unhandled_route: RouteKey
    keys: Tuple[str, ...]


# -------------------------
# Stamping helper (used by Elk.emit)
# -------------------------

def stamp_event(
    evt: Event,
    *,
    at: float,
    seq: Optional[int],
    classification: str,
    route: RouteKey,
    session_id: Optional[int],
) -> Event:
    """
    Replace the common header fields on an event.
    Elk.emit() uses this to make headers authoritative and consistent.
    """
    return replace(
        evt,
        at=at,
        seq=seq,
        classification=classification,
        route=route,
        session_id=session_id,
    )
