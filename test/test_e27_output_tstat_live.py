from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import pytest

from elke27_lib import Elk
from elke27_lib import linking
from elke27_lib.events import (
    ApiError,
    OutputStatusUpdated,
    OutputsStatusBulkUpdated,
    TstatStatusUpdated,
)
from elke27_lib.session import SessionConfig


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    if value == "":
        return default
    return value


def _require_env(name: str) -> str:
    value = _env(name)
    if not value:
        pytest.skip(f"Missing {name} for live output/tstat tests.")
    return value


@dataclass(frozen=True, slots=True)
class _Credentials:
    access_code: str
    passphrase: str


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_output_and_tstat_status() -> None:
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
    output_id = int(_env("ELKE27_OUTPUT_ID", "1") or 1)
    tstat_id = int(_env("ELKE27_TSTAT_ID", "1") or 1)

    identity = linking.E27Identity(mn=mn, sn=sn, fwver=fwver, hwver=hwver, osver=osver)
    elk = Elk(features=["elke27_lib.features.output", "elke27_lib.features.tstat"])

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

    seq = elk.request(("output", "get_status"), output_id=output_id)
    print(f"Sent output.get_status seq={seq}")

    output_seen = False
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        elk.session.pump_once(timeout_s=0.5)
        for evt in elk.drain_events():
            if evt.kind == ApiError.KIND:
                await elk.close()
                pytest.skip(f"output.get_status not supported: error_code={evt.error_code}")
            if evt.kind == OutputStatusUpdated.KIND and evt.output_id == output_id:
                output_seen = True
                print(f"Output {output_id} status: {evt.status}")
                break
        if output_seen:
            break

    if not output_seen:
        await elk.close()
        pytest.fail("Timed out waiting for OutputStatusUpdated event.")

    seq = elk.request(("output", "get_all_outputs_status"))
    print(f"Sent output.get_all_outputs_status seq={seq}")

    bulk_seen = False
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        elk.session.pump_once(timeout_s=0.5)
        for evt in elk.drain_events():
            if evt.kind == ApiError.KIND:
                await elk.close()
                pytest.skip(f"output.get_all_outputs_status not supported: error_code={evt.error_code}")
            if evt.kind == OutputsStatusBulkUpdated.KIND:
                bulk_seen = True
                print(f"Outputs bulk updated count: {evt.updated_count}")
                break
        if bulk_seen:
            break

    if not bulk_seen:
        await elk.close()
        pytest.fail("Timed out waiting for OutputsStatusBulkUpdated event.")

    seq = elk.request(("tstat", "get_status"), tstat_id=tstat_id)
    print(f"Sent tstat.get_status seq={seq}")

    tstat_seen = False
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        elk.session.pump_once(timeout_s=0.5)
        for evt in elk.drain_events():
            if evt.kind == ApiError.KIND:
                await elk.close()
                if evt.error_code == 11006:
                    print("tstat.get_status returned invalid_id (no thermostats installed).")
                    return
                pytest.skip(f"tstat.get_status not supported: error_code={evt.error_code}")
            if evt.kind == TstatStatusUpdated.KIND and evt.tstat_id == tstat_id:
                tstat_seen = True
                print(f"Tstat {tstat_id} temp: {evt.temperature} mode={evt.mode}")
                break
        if tstat_seen:
            break

    await elk.close()
    if not tstat_seen:
        pytest.fail("Timed out waiting for TstatStatusUpdated event.")
