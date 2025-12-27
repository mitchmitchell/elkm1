from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import pytest

from elke27_lib import Elk
from elke27_lib import linking
from elke27_lib.events import ApiError, ZoneDefFlagsUpdated, ZoneDefsUpdated
from elke27_lib.session import SessionConfig


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    if value == "":
        return default
    return value


def _require_env(name: str) -> str:
    value = _env(name)
    if not value:
        pytest.skip(f"Missing {name} for live zone defs test.")
    return value


@dataclass(frozen=True, slots=True)
class _Credentials:
    access_code: str
    passphrase: str


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_zone_defs_and_flags() -> None:
    log_level = str(_env("LOG_LEVEL", "INFO") or "INFO").upper()
    logging.basicConfig(level=getattr(logging, log_level, logging.INFO), force=True)
    logging.getLogger("elke27_lib.session").setLevel(logging.DEBUG)

    host = _require_env("ELKE27_HOST")
    port = int(_env("ELKE27_PORT", "2101") or 2101)
    access_code = _require_env("ELKE27_ACCESS_CODE")
    passphrase = _require_env("ELKE27_PASSPHRASE")
    mn = _require_env("ELKE27_MN")
    sn = _require_env("ELKE27_SN")
    fwver = _require_env("ELKE27_FWVER")
    hwver = _require_env("ELKE27_HWVER")
    osver = _require_env("ELKE27_OSVER")
    timeout_s = float(_env("ELKE27_TIMEOUT_S", "10.0") or 10.0)

    identity = linking.E27Identity(mn=mn, sn=sn, fwver=fwver, hwver=hwver, osver=osver)
    elk = Elk(features=["elke27_lib.features.zone"])

    panel = {"host": host, "port": port}
    creds = _Credentials(access_code=access_code, passphrase=passphrase)
    link_keys = await elk.link(panel, identity, creds, timeout_s=timeout_s)
    session_cfg = SessionConfig(host=host, port=port, hello_timeout_s=timeout_s)
    await elk.connect(link_keys, session_config=session_cfg)

    pin_value = _env("ELKE27_PIN")
    if pin_value:
        pin = int(pin_value)
        auth_msg = {"seq": 110, "authenticate": {"pin": pin}}
        elk.session.send_json(auth_msg)
        auth_reply = elk.session.recv_json(timeout_s=2.0)
        print(f"Authenticate reply: {auth_reply}")

    seq = elk.request(("zone", "get_defs"), block_id=1)
    print(f"Sent zone.get_defs seq={seq}")
    if not _wait_for_event(elk, ZoneDefsUpdated.KIND, timeout_s):
        await elk.close()
        pytest.fail("Timed out waiting for ZoneDefsUpdated event.")

    definition = _first_definition(elk)
    if not definition:
        await elk.close()
        pytest.skip("No zone definitions available to query flags.")

    seq = elk.request(("zone", "get_def_flags"), definition=definition)
    print(f"Sent zone.get_def_flags seq={seq}")
    if not _wait_for_event(elk, ZoneDefFlagsUpdated.KIND, timeout_s):
        await elk.close()
        pytest.fail("Timed out waiting for ZoneDefFlagsUpdated event.")

    await elk.close()


def _wait_for_event(elk: Elk, kind: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        elk.session.pump_once(timeout_s=0.5)
        for evt in elk.drain_events():
            if evt.kind == ApiError.KIND:
                pytest.skip(f"{kind} failed with error_code={evt.error_code}")
            if evt.kind == kind:
                return True
    return False


def _first_definition(elk: Elk) -> str | None:
    for entry in elk.state.zone_defs_by_id.values():
        definition = entry.get("definition")
        if isinstance(definition, str) and definition.strip():
            return definition
    return None
