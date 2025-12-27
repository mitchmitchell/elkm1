#!/usr/bin/env python3
"""
e27_api_link.py

Provisioning example: perform API_LINK via Elk.link() and print link credentials.

This is a provisioning-time operation. It does NOT:
- start the framed/encrypted session protocol
- perform authentication
- send operational panel requests

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
from dataclasses import dataclass
from typing import Optional

from elke27_lib import Elk
from elke27_lib import linking

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


async def main_async() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=10.0, help="Socket/provisioning timeout seconds")
    ap.add_argument("--address", type=str, default=None, help="Optional broadcast address override")

    # Panel selection
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

    # Identity (sent during API_LINK / HELLO)
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

    # Credentials
    ap.add_argument(
        "--access-code",
        default=_env_any(["ELKE27_ACCESS_CODE", "ELK_ACCESS_CODE"], ""),
        help="Access code (installer/user)",
    )
    ap.add_argument(
        "--passphrase",
        default=_env_any(["ELKE27_PASSPHRASE", "ELK_PASSPHRASE"], ""),
        help="Provisioning passphrase",
    )
    args = ap.parse_args()

    if not args.mn or not args.sn:
        raise SystemExit("ERROR: identity requires --mn and --sn (or ELK_MN / ELK_SN).")

    if not args.access_code or not args.passphrase:
        raise SystemExit("ERROR: credentials require --access-code and --passphrase (or env vars).")

    # Choose panel
    if args.host:
        panel = {"host": args.host, "port": args.port}
    else:
        discovered = await Elk.discover(timeout=int(args.timeout), address=args.address)
        if not discovered.panels:
            raise SystemExit("ERROR: no panels discovered. Provide --host/--port or fix discovery environment.")
        print("\nDiscovered panels:")
        for panel_info in discovered.panels:
            print(f"  - {panel_info}")
        panel = discovered.panels[0]

    elk = Elk(features=[])

    identity = linking.E27Identity(
        mn=str(args.mn),
        sn=str(args.sn),
        fwver=str(args.fwver),
        hwver=str(args.hwver),
        osver=str(args.osver),
    )
    creds = E27Credentials(access_code=str(args.access_code), passphrase=str(args.passphrase))

    link_keys = await elk.link(panel, identity, creds, timeout_s=float(args.timeout))

    print("\nProvisioned credentials (store securely):")
    print(f"  tempkey_hex:  {link_keys.tempkey_hex}")
    print(f"  linkkey_hex:  {link_keys.linkkey_hex}")
    print(f"  linkhmac_hex: {link_keys.linkhmac_hex}")
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("elke27_lib.linking").setLevel(logging.DEBUG)
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
