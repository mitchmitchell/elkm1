"""
elke27_lib/states.py

PanelState v0 (minimal, handler-friendly, HA-friendly).

Principles:
- IDs are 1-based; store by integer id without renumbering.
- Patch-style updates: handlers update only fields present in payloads.
- Timestamps use monotonic time (provided by Elk).
- No I/O, no logging, no protocol knowledge here—this is pure state storage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


# -------------------------
# Panel-level state
# -------------------------

@dataclass(slots=True)
class PanelMetaState:
    """
    Small "panel header" state owned by Elk and updated by handlers.
    """
    session_id: Optional[int] = None
    connected: bool = False

    # Monotonic timestamp of last message seen/processed.
    last_message_at: Optional[float] = None

    # Optional panel/version info (filled when handlers decode device/version payloads)
    model: Optional[str] = None
    firmware: Optional[str] = None
    serial: Optional[str] = None


# -------------------------
# Area state
# -------------------------

@dataclass(slots=True)
class AreaState:
    area_id: int

    # Identity/config
    name: Optional[str] = None

    # Core status (strings depend on API enums; keep as str for now)
    armed_state: Optional[str] = None
    alarm_state: Optional[str] = None
    alarm_event: Optional[str] = None
    arm_state: Optional[str] = None
    ready_status: Optional[str] = None

    # Common flags
    ready: Optional[bool] = None
    stay: Optional[bool] = None
    away: Optional[bool] = None
    bypass: Optional[bool] = None
    chime: Optional[bool] = None
    entry_delay_active: Optional[bool] = None
    exit_delay_active: Optional[bool] = None
    trouble: Optional[bool] = None

    # Common counts (if reported)
    num_not_ready_zones: Optional[int] = None
    num_bypassed_zones: Optional[int] = None

    # Response/error tracking
    last_error_code: Optional[int] = None

    # Troubles list for area.get_troubles
    troubles: Optional[list[str]] = None

    # Monotonic timestamp of last update to this area
    last_update_at: Optional[float] = None


# -------------------------
# Zone state (stub v0)
# -------------------------

@dataclass(slots=True)
class ZoneState:
    zone_id: int

    name: Optional[str] = None
    area_id: Optional[int] = None
    definition: Optional[str] = None
    flags: Optional[list[dict]] = None

    enabled: Optional[bool] = None
    bypassed: Optional[bool] = None
    violated: Optional[bool] = None
    trouble: Optional[bool] = None
    tamper: Optional[bool] = None
    alarm: Optional[bool] = None

    # Bulk status code (see zone.get_all_zones_status)
    status_code: Optional[str] = None
    attribs: Dict[str, object] = field(default_factory=dict)

    last_update_at: Optional[float] = None


# -------------------------
# Trouble state (stub v0)
# -------------------------

@dataclass(slots=True)
class TroubleState:
    active: Optional[bool] = None
    last_update_at: Optional[float] = None

    # Optional future expansion: named trouble bits, raw snapshots, etc.
    # bits: Dict[str, bool] = field(default_factory=dict)


@dataclass(slots=True)
class NetworkState:
    ssid_scan_results: list[Dict[str, object]] = field(default_factory=list)
    rssi: Optional[int] = None
    last_update_at: Optional[float] = None


# -------------------------
# Output/Tstat state
# -------------------------

@dataclass(slots=True)
class OutputState:
    output_id: int

    name: Optional[str] = None
    status: Optional[str] = None
    on: Optional[bool] = None
    status_code: Optional[str] = None
    fields: Dict[str, object] = field(default_factory=dict)
    last_update_at: Optional[float] = None


@dataclass(slots=True)
class TstatState:
    tstat_id: int

    name: Optional[str] = None
    temperature: Optional[int] = None
    cool_setpoint: Optional[int] = None
    heat_setpoint: Optional[int] = None
    mode: Optional[str] = None
    fan_mode: Optional[str] = None
    humidity: Optional[int] = None
    rssi: Optional[int] = None
    battery_level: Optional[int] = None
    prec: Optional[list[int]] = None
    fields: Dict[str, object] = field(default_factory=dict)
    last_update_at: Optional[float] = None


# -------------------------
# Root state container
# -------------------------

@dataclass(slots=True)
class PanelState:
    panel: PanelMetaState = field(default_factory=PanelMetaState)

    # Domain containers keyed by id
    areas: Dict[int, AreaState] = field(default_factory=dict)
    zones: Dict[int, ZoneState] = field(default_factory=dict)
    configured_zone_ids: set[int] = field(default_factory=set)
    zone_defs_by_id: Dict[int, Dict[str, object]] = field(default_factory=dict)
    zone_def_flags_by_id: Dict[int, Dict[str, object]] = field(default_factory=dict)
    zone_def_flags_by_name: Dict[str, Dict[str, object]] = field(default_factory=dict)
    outputs: Dict[int, OutputState] = field(default_factory=dict)
    tstats: Dict[int, TstatState] = field(default_factory=dict)

    troubles: TroubleState = field(default_factory=TroubleState)
    network: NetworkState = field(default_factory=NetworkState)
    table_info_by_domain: Dict[str, Dict[str, object]] = field(default_factory=dict)

    # Debug storage (off by default; Elk/handlers can choose to fill)
    debug_last_raw_by_route_enabled: bool = False
    debug_last_raw_by_route: Dict[str, dict] = field(default_factory=dict)

    def get_or_create_area(self, area_id: int) -> AreaState:
        """
        Retrieve an AreaState by id; create if missing.
        """
        area = self.areas.get(area_id)
        if area is None:
            area = AreaState(area_id=area_id)
            self.areas[area_id] = area
        return area

    def get_or_create_zone(self, zone_id: int) -> ZoneState:
        """
        Retrieve a ZoneState by id; create if missing.
        """
        zone = self.zones.get(zone_id)
        if zone is None:
            zone = ZoneState(zone_id=zone_id)
            self.zones[zone_id] = zone
        return zone

    def get_or_create_output(self, output_id: int) -> OutputState:
        output = self.outputs.get(output_id)
        if output is None:
            output = OutputState(output_id=output_id)
            self.outputs[output_id] = output
        return output

    def get_or_create_tstat(self, tstat_id: int) -> TstatState:
        tstat = self.tstats.get(tstat_id)
        if tstat is None:
            tstat = TstatState(tstat_id=tstat_id)
            self.tstats[tstat_id] = tstat
        return tstat
