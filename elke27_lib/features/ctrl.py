"""
elke27_lib/features/ctrl.py

Feature module: ctrl

Responsibilities:
- Register inbound handlers for ctrl.*
- Register outbound request builders for ctrl.* routes

Current scope:
- ("ctrl","get_version_info") only
"""

from __future__ import annotations

from typing import Any

from elke27_lib.handlers.ctrl import make_ctrl_get_version_info_handler


ROUTE_CTRL_GET_VERSION_INFO = ("control", "get_version_info")


def register(elk) -> None:
    # Inbound handler
    elk.register_handler(
        ROUTE_CTRL_GET_VERSION_INFO,
        make_ctrl_get_version_info_handler(elk.state, elk.emit, elk.now),
    )

    # Outbound request builder (payload only; Elk builds seq/session_id/envelope)
    elk.register_request(
        ROUTE_CTRL_GET_VERSION_INFO,
        build_ctrl_get_version_info_payload,
    )


def build_ctrl_get_version_info_payload(**kwargs: Any) -> int:
    # No parameters required for v0
    return 0
