"""
elke27_lib/features/control.py

Feature module: control

Responsibilities:
- Register inbound handlers for control.*
- Register outbound request builders for control.* routes

Current scope:
- ("control","get_version_info") only
"""

from __future__ import annotations

from typing import Any

from elke27_lib.handlers.control import make_control_get_version_info_handler


ROUTE_CONTROL_GET_VERSION_INFO = ("control", "get_version_info")


def register(elk) -> None:
    # Inbound handler
    elk.register_handler(
        ROUTE_CONTROL_GET_VERSION_INFO,
        make_control_get_version_info_handler(elk.state, elk.emit, elk.now),
    )

    # Outbound request builder (payload only; Elk builds seq/session_id/envelope)
    elk.register_request(
        ROUTE_CONTROL_GET_VERSION_INFO,
        build_control_get_version_info_payload,
    )


def build_control_get_version_info_payload(**kwargs: Any) -> dict:
    # No parameters required for v0
    return {}
