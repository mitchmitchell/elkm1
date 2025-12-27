#!/usr/bin/env python3
"""
e27_aioscanner.py

Example: discover E27 panels on the network using the Elk facade.

This uses:
  Elk.discover() -> discovery.AIOELKDiscovery.async_scan()

No linking. No session connect.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import pprint

from elke27_lib import Elk

LOG = logging.getLogger(__name__)


async def main_async() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=10, help="Discovery scan timeout in seconds")
    ap.add_argument("--address", type=str, default=None, help="Optional broadcast address override")
    args = ap.parse_args()

    result = await Elk.discover(timeout=args.timeout, address=args.address)

    print("\nDiscovered panels:")
    if not result.panels:
        print("  (none)")
        return 0

    # ElkSystem is dataclass-like; pprint handles it well
    pprint.pprint(result.panels)
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
