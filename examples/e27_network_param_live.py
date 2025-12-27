#!/usr/bin/env python3
"""
e27_network_param_live.py

Live example: discover -> link -> connect -> network.get_ssid + network.get_rssi
with call-site authorization retry (PIN prompt).
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
from elke27_lib.events import ApiError, NetworkRssiUpdated, NetworkSsidResultsUpdated
from elke27_lib.session import SessionConfig

LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class E27Credentials:
    access_code: str
    passphrase: str


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    import os
    value = os.environ.get(name, default)
    if value == "":
        return default
    return value


def _env_any(names: list[str], default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = _env(name)
        if value:
            return value
    return default


def _prompt_pin() -> Optional[int]:
    pin = _env("ELKE27_PIN")
    if pin:
        pin = pin.strip()
    else:
        pin = input("Panel requires authorization. Enter PIN: ").strip()

    if not pin.isdigit() or not (4 <= len(pin) <= 6):
        print("ERROR: PIN must be 4–6 digits.")
        return None
    return int(pin)


def _dict_auth_required(obj: dict) -> bool:
    net = obj.get("network")
    if not isinstance(net, dict):
        return False
    error_code = net.get("error_code")
    if isinstance(error_code, str):
        try:
            error_code = int(error_code)
        except ValueError:
            return False
    if error_code == 11008:
        return True
    return False


def _wait_for_network_event(elk: Elk, kind: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        obj = elk.session.pump_once(timeout_s=0.5)
        if isinstance(obj, dict) and _dict_auth_required(obj):
            return "auth_required", None

        for evt in elk.drain_events():
            if evt.kind == kind:
                return "ok", evt
            if evt.kind == ApiError.KIND and evt.error_code == 11008 and evt.scope == "network":
                return "auth_required", evt
            if evt.kind == ApiError.KIND and evt.scope == "network":
                return "error", evt

    return "timeout", None


def _authenticate(elk: Elk, *, pin: int) -> None:
    auth_msg = {"seq": 110, "authenticate": {"pin": pin}}
    elk.session.send_json(auth_msg)
    try:
        reply = elk.session.recv_json(timeout_s=2.0)
        print(f"Authenticate reply: {reply}")
    except Exception as exc:
        print(f"Authenticate reply read failed: {exc}")


async def _run_with_auth_retry(
    elk: Elk,
    route: tuple[str, str],
    *,
    success_kind: str,
    description: str,
    timeout_s: float,
) -> bool:
    attempt = 0
    while attempt < 2:
        attempt += 1
        seq = elk.request(route)
        print(f"Sent {description} seq={seq}")

        status, evt = _wait_for_network_event(elk, success_kind, timeout_s)
        if status == "ok":
            return True
        if status == "error":
            assert isinstance(evt, ApiError)
            print(f"{description} failed with error_code={evt.error_code} message={evt.message!r}")
            return False
        if status == "timeout":
            print(f"Timed out waiting for {description} response.")
            return False

        if status == "auth_required":
            if attempt > 1:
                print("Authorization still required (PIN rejected or insufficient privileges).")
                return False
            print(f"Authorization required for {description}; authenticating…")
            pin = _prompt_pin()
            if pin is None:
                return False
            _authenticate(elk, pin=pin)
            print(f"Authenticated; retrying {description}…")

    return False


async def main_async() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=10.0, help="Overall timeout for request/response")
    ap.add_argument("--address", type=str, default=None, help="Optional discovery broadcast address override")
    ap.add_argument("--log-level", default=_env_any(["LOG_LEVEL"], "INFO"), help="DEBUG/INFO/WARNING/ERROR")
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

    # Panel selection
    if args.host:
        panel = {"host": args.host, "port": args.port}
    else:
        discovered = await Elk.discover(timeout=int(args.timeout), address=args.address)
        if not discovered.panels:
            raise SystemExit("ERROR: no panels discovered.")
        panel = discovered.panels[0]

    elk = Elk(features=["elke27_lib.features.network_param"])

    identity = linking.E27Identity(
        mn=str(mn),
        sn=str(sn),
        fwver=str(_env_any(["ELKE27_FWVER", "ELK_FWVER"], "0") or "0"),
        hwver=str(_env_any(["ELKE27_HWVER", "ELK_HWVER"], "0") or "0"),
        osver=str(_env_any(["ELKE27_OSVER", "ELK_OSVER"], "0") or "0"),
    )
    creds = E27Credentials(access_code=access_code, passphrase=passphrase)

    link_keys = await elk.link(panel, identity, creds, timeout_s=float(args.timeout))
    if isinstance(panel, dict):
        panel_host = panel.get("host") or panel.get("ip_address")
        panel_port = int(panel.get("port") or 2101)
    else:
        panel_host = panel.ip_address
        panel_port = int(panel.port)

    session_cfg = SessionConfig(host=panel_host, port=panel_port, hello_timeout_s=float(args.timeout))
    await elk.connect(link_keys, session_config=session_cfg)

    ok = await _run_with_auth_retry(
        elk,
        ("network", "get_ssid"),
        success_kind=NetworkSsidResultsUpdated.KIND,
        description="network.get_ssid",
        timeout_s=float(args.timeout),
    )
    if ok:
        results = elk.state.network.ssid_scan_results
        print(f"SSID results: {[r.get('ssid') for r in results if isinstance(r, dict)]}")

    ok = await _run_with_auth_retry(
        elk,
        ("network", "get_rssi"),
        success_kind=NetworkRssiUpdated.KIND,
        description="network.get_rssi",
        timeout_s=float(args.timeout),
    )
    if ok:
        print(f"RSSI: {elk.state.network.rssi}")

    await elk.close()
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
