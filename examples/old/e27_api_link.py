#!/usr/bin/env python3
"""
examples/e27_api_link.py

E27 provisioning tool: perform API_LINK to obtain link credentials.

What this does
- Opens a plain TCP connection to the E27 panel (default port 2101).
- Waits for the cleartext discovery hello that includes the discovery nonce.
- Performs API_LINK (clear + UNFRAMED) to provision the application on the panel.
- Prints the resulting link credentials (link key + link HMAC) you will use later for HELLO/session crypto.

What this does NOT do
- It does not start the framed/encrypted session protocol.
- It does not perform authentication, nor any writes to panel entities.
- It does not modify dispatcher/session behavior; this is a standalone provisioning step.

Inputs required
- host / port
- access_code (installer/user access code for linking)
- passphrase  (linking passphrase)
- identity fields required by the protocol (mn/sn/fwver/hwver/osver)

Environment variables supported
- ELKE27_HOST
- ELKE27_PORT (default 2101)
- ELKE27_ACCESS_CODE
- ELKE27_PASSPHRASE
- ELKE27_MN
- ELKE27_SN
- ELKE27_FWVER
- ELKE27_HWVER
- ELKE27_OSVER

Example
  ELKE27_HOST=192.168.1.50 \
  ELKE27_ACCESS_CODE=1234 \
  ELKE27_PASSPHRASE="my passphrase" \
  ELKE27_MN=E27 ELKE27_SN=12345678 ELKE27_FWVER=1.0 ELKE27_HWVER=1.0 ELKE27_OSVER=1.0 \
  python examples/e27_api_link.py
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
from dataclasses import asdict
from typing import Optional

from elke27_lib.linking import E27Identity, perform_api_link, wait_for_discovery_nonce


LOG = logging.getLogger(__name__)


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _require(name: str, value: Optional[str]) -> str:
    if value is None or value == "":
        raise SystemExit(f"Missing required value for {name}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="E27 provisioning: API_LINK to obtain link credentials")
    parser.add_argument("--host", default=_env("ELKE27_HOST"), help="Panel IP/host (or ELKE27_HOST)")
    parser.add_argument("--port", type=int, default=int(_env("ELKE27_PORT", "2101")), help="Panel port (default 2101)")

    parser.add_argument("--access-code", default=_env("ELKE27_ACCESS_CODE"), help="Linking access code")
    parser.add_argument("--passphrase", default=_env("ELKE27_PASSPHRASE"), help="Linking passphrase")

    parser.add_argument("--mn", default=_env("ELKE27_MN"), help="Identity MN (required)")
    parser.add_argument("--sn", default=_env("ELKE27_SN"), help="Identity SN (required)")
    parser.add_argument("--fwver", default=_env("ELKE27_FWVER"), help="Identity FWVER (required)")
    parser.add_argument("--hwver", default=_env("ELKE27_HWVER"), help="Identity HWVER (required)")
    parser.add_argument("--osver", default=_env("ELKE27_OSVER"), help="Identity OSVER (required)")

    parser.add_argument("--timeout-s", type=float, default=10.0, help="Timeout for discovery nonce + api_link")
    parser.add_argument("--log-level", default=_env("LOG_LEVEL", "INFO"), help="DEBUG/INFO/WARNING/ERROR")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO), format="%(message)s")

    host = _require("--host/ELKE27_HOST", args.host)
    access_code = _require("--access-code/ELKE27_ACCESS_CODE", args.access_code)
    passphrase = _require("--passphrase/ELKE27_PASSPHRASE", args.passphrase)

    identity = E27Identity(
        mn=_require("--mn/ELKE27_MN", args.mn),
        sn=_require("--sn/ELKE27_SN", args.sn),
        fwver=_require("--fwver/ELKE27_FWVER", args.fwver),
        hwver=_require("--hwver/ELKE27_HWVER", args.hwver),
        osver=_require("--osver/ELKE27_OSVER", args.osver),
    )

    LOG.info("Connecting (clear TCP) to %s:%s ...", host, args.port)
    with socket.create_connection((host, args.port), timeout=5.0) as sock:
        # 1) Wait for discovery nonce (panel cleartext hello)
        LOG.info("Waiting for discovery nonce ...")
        discovery_nonce = wait_for_discovery_nonce(sock, timeout_s=args.timeout_s)
        LOG.info("Discovery nonce: %s", discovery_nonce)

        # 2) API_LINK provisioning (clear, UNFRAMED)
        LOG.info("Performing API_LINK ...")
        result = perform_api_link(
            sock=sock,
            identity=identity,
            access_code=access_code,
            passphrase=passphrase,
            mn_for_hash=identity.mn,
            discovery_nonce=discovery_nonce,
        )

    # Handle return type variations (some branches returned tuple historically)
    linkkey_hex: Optional[str] = None
    linkhmac_hex: Optional[str] = None

    if isinstance(result, tuple):
        # Historically: (tempkey_hex, linkkey_hex, linkhmac_hex) or similar
        if len(result) >= 2:
            linkkey_hex = result[1] or None
        if len(result) >= 3:
            linkhmac_hex = result[2] or None
    else:
        # Preferred: LinkCredentials dataclass (linkkey_hex, linkhmac_hex)
        linkkey_hex = getattr(result, "linkkey_hex", None)
        linkhmac_hex = getattr(result, "linkhmac_hex", None)

    if not linkkey_hex or not linkhmac_hex:
        LOG.error("API_LINK did not yield link credentials (result=%r)", result)
        return 1

    print("\n=== API_LINK SUCCESS ===")
    print("Identity:")
    for k, v in asdict(identity).items():
        print(f"  {k}: {v}")
    print("\nProvisioned credentials (store these securely):")
    print(f"  link_key_hex:  {linkkey_hex}")
    print(f"  link_hmac_hex: {linkhmac_hex}")
    print("\nNext step: use link_key_hex for normal session HELLO/crypto in your live test program.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
