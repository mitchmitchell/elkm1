#!/usr/bin/env python3
"""
e27_live_version_info.py

Live example: discover -> link -> connect (HELLO) -> control.get_version_info -> print PanelState.

NOTE:
- This example performs provisioning (API_LINK) via elk.link() so it can be run standalone.
- If you want “no provisioning” runs, we should add a dedicated Elk method to set context
  from an existing link key without calling link(). (Not implemented yet.)

Environment variables (optional):
  ELKE27_HOST, ELKE27_PORT
  ELKE27_MN, ELKE27_SN, ELKE27_FWVER, ELKE27_HWVER, ELKE27_OSVER
  ELKE27_ACCESS_CODE, ELKE27_PASSPHRASE
  ELK_HOST, ELK_PORT
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
from elke27_lib.session import SessionState

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
    ap.add_argument("--pin", type=int, default=None, help="Optional pin for authenticate diagnostic")
    ap.add_argument("--auth-only", action="store_true", help="Exit after authenticate diagnostic reply")
    ap.add_argument(
        "--host",
        type=str,
        default=_env_any(["ELKE27_HOST", "ELK_HOST"], None),
        help="Panel IP/host (skip discovery)",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=int(_env_any(["ELKE27_PORT", "ELK_PORT"], "2101") or 2101),
        help="Panel port (default 2101)",
    )

    ap.add_argument("--mn", default=_env_any(["ELKE27_MN", "ELK_MN"], ""), help="Manufacturer number (MN)")
    ap.add_argument("--sn", default=_env_any(["ELKE27_SN", "ELK_SN"], ""), help="Serial number (SN)")
    ap.add_argument(
        "--fwver",
        default=_env_any(["ELKE27_FWVER", "ELK_FWVER"], "0"),
        help="Firmware version",
    )
    ap.add_argument(
        "--hwver",
        default=_env_any(["ELKE27_HWVER", "ELK_HWVER"], "0"),
        help="Hardware version",
    )
    ap.add_argument(
        "--osver",
        default=_env_any(["ELKE27_OSVER", "ELK_OSVER"], "0"),
        help="OS version",
    )

    ap.add_argument(
        "--access-code",
        default=_env_any(["ELKE27_ACCESS_CODE", "ELK_ACCESS_CODE"], ""),
        help="Access code",
    )
    ap.add_argument(
        "--passphrase",
        default=_env_any(["ELKE27_PASSPHRASE", "ELK_PASSPHRASE"], ""),
        help="Provisioning passphrase",
    )
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO))

    if not args.mn or not args.sn:
        raise SystemExit("ERROR: identity requires --mn and --sn (or ELK_MN / ELK_SN).")
    if not args.access_code or not args.passphrase:
        raise SystemExit("ERROR: credentials require --access-code and --passphrase (or env vars).")

    # Panel selection
    if args.host:
        panel = {"host": args.host, "port": args.port}
    else:
        discovered = await Elk.discover(timeout=int(args.timeout), address=args.address)
        if not discovered.panels:
            raise SystemExit("ERROR: no panels discovered. Provide --host/--port or fix discovery environment.")
        panel = discovered.panels[0]

    elk = Elk()

    identity = linking.E27Identity(
        mn=str(args.mn),
        sn=str(args.sn),
        fwver=str(args.fwver),
        hwver=str(args.hwver),
        osver=str(args.osver),
    )
    creds = E27Credentials(access_code=str(args.access_code), passphrase=str(args.passphrase))

    link_keys = await elk.link(panel, identity, creds, timeout_s=float(args.timeout))

    if isinstance(panel, dict):
        panel_host = panel.get("host") or panel.get("ip_address")
        panel_port = int(panel.get("port") or 2101)
    else:
        panel_host = panel.ip_address
        panel_port = int(panel.port)

    from elke27_lib.session import SessionConfig

    session_cfg = SessionConfig(
        host=panel_host,
        port=panel_port,
        hello_timeout_s=float(args.timeout),
        wire_log=bool(args.wire_log),
    )
    state = await elk.connect(link_keys, session_config=session_cfg)
    print(f"Session state: {state}")
    if state is not SessionState.ACTIVE:
        raise SystemExit(f"ERROR: session not ACTIVE (state={state})")

    if args.pin is not None:
        auth_msg = {"seq": 110, "authenticate": {"pin": int(args.pin)}}
        elk.session.send_json(auth_msg)
        auth_reply = elk.session.recv_json(timeout_s=2.0)
        print(f"Authenticate reply: {auth_reply}")
        if args.auth_only:
            await elk.close()
            return 0

    # seq = elk.request(("control", "get_version_info"))
    # print(f"Sent control.get_version_info seq={seq}")

    # deadline = time.monotonic() + float(args.timeout)

    # while time.monotonic() < deadline:
    #     # Drive inbound receive -> dispatch -> events
    #     elk.session.pump_once(timeout_s=float(args.pump_s))

    #     for evt in elk.drain_events():
    #         if evt.kind == PanelVersionInfoUpdated.KIND:
    #             print("\nPanel version info updated:")
    #             print(f"  session_id     = {elk.state.panel.session_id}")
    #             print(f"  connected      = {elk.state.panel.connected}")
    #             print(f"  last_message_at= {elk.state.panel.last_message_at}")
    #             print(f"  model          = {elk.state.panel.model}")
    #             print(f"  firmware       = {elk.state.panel.firmware}")
    #             print(f"  serial         = {elk.state.panel.serial}")
    #             await elk.close()
    #             return 0

    #     await asyncio.sleep(0)  # yield

    # print("Timed out waiting for PanelVersionInfoUpdated event.")
    await elk.close()
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
