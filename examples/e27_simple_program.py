#!/usr/bin/env python3
"""
e27simple_program.py

Minimal "hello world" style example using the new Elk facade:
- discover -> link -> connect
- request control.get_version_info
- pump until event arrives

Environment variables (optional):
  ELKE27_MN, ELKE27_SN, ELKE27_FWVER, ELKE27_HWVER, ELKE27_OSVER
  ELKE27_ACCESS_CODE, ELKE27_PASSPHRASE
  ELK_MN, ELK_SN, ELK_FWVER, ELK_HWVER, ELK_OSVER
  ELK_ACCESS_CODE, ELK_PASSPHRASE
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional

from elke27_lib import Elk
from elke27_lib import linking
from elke27_lib.events import PanelVersionInfoUpdated
from elke27_lib.session import SessionConfig

LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class E27Credentials:
    access_code: str
    passphrase: str


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    import os
    return os.environ.get(name, default)


def _env_any(names: list[str], default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = _env(name)
        if value:
            return value
    return default


def _truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


async def main_async() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=10.0, help="Overall timeout for request/response")
    ap.add_argument("--pump-s", type=float, default=0.25, help="Per-pump timeout")
    ap.add_argument("--address", type=str, default=None, help="Optional discovery broadcast address override")
    ap.add_argument("--log-level", default=_env_any(["LOG_LEVEL"], "INFO"), help="DEBUG/INFO/WARNING/ERROR")
    ap.add_argument(
        "--wire-log",
        action="store_true",
        default=_truthy(_env_any(["ELKE27_WIRE_LOG", "ELK_WIRE_LOG"], None)),
        help="Enable raw RX/TX hex dump logging",
    )
    args = ap.parse_args()

    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO))

    mn = _env_any(["ELKE27_MN", "ELK_MN"], "")
    sn = _env_any(["ELKE27_SN", "ELK_SN"], "")
    access_code = _env_any(["ELKE27_ACCESS_CODE", "ELK_ACCESS_CODE"], "")
    passphrase = _env_any(["ELKE27_PASSPHRASE", "ELK_PASSPHRASE"], "")

    if not mn or not sn:
        raise SystemExit("ERROR: set ELK_MN and ELK_SN (identity).")
    if not access_code or not passphrase:
        raise SystemExit("ERROR: set ELK_ACCESS_CODE and ELK_PASSPHRASE (provisioning).")

    elk = Elk()

    discovered = await Elk.discover(timeout=int(args.timeout), address=args.address)
    if not discovered.panels:
        raise SystemExit("ERROR: no panels discovered.")

    panel = discovered.panels[0]
    panel_host = panel.ip_address
    panel_port = int(panel.port)
    identity = linking.E27Identity(
        mn=mn,
        sn=sn,
        fwver=_env_any(["ELKE27_FWVER", "ELK_FWVER"], "0") or "0",
        hwver=_env_any(["ELKE27_HWVER", "ELK_HWVER"], "0") or "0",
        osver=_env_any(["ELKE27_OSVER", "ELK_OSVER"], "0") or "0",
    )
    creds = E27Credentials(access_code=access_code, passphrase=passphrase)

    link_keys = await elk.link(panel, identity, creds, timeout_s=float(args.timeout))
    session_cfg = SessionConfig(
        host=panel_host,
        port=panel_port,
        hello_timeout_s=float(args.timeout),
        wire_log=bool(args.wire_log),
    )
    await elk.connect(link_keys, session_config=session_cfg)

    elk.request(("control", "get_version_info"))

    deadline = time.monotonic() + float(args.timeout)
    while time.monotonic() < deadline:
        elk.session.pump_once(timeout_s=float(args.pump_s))

        for evt in elk.drain_events():
            if evt.kind == PanelVersionInfoUpdated.KIND:
                print("Connected and received version info:")
                print(f"  session_id = {elk.state.panel.session_id}")
                print(f"  model      = {elk.state.panel.model}")
                print(f"  firmware   = {elk.state.panel.firmware}")
                print(f"  serial     = {elk.state.panel.serial}")
                await elk.close()
                return 0

        await asyncio.sleep(0)

    print("Timed out waiting for version info.")
    await elk.close()
    return 1


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
