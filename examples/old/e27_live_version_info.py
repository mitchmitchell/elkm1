#!/usr/bin/env python3
"""
examples/e27_live_version_info.py

E27 live test example: connect + HELLO + request control.get_version_info + print results.

Assumptions / scope:
- Linking (API_LINK) has already been done out-of-band and you have a link key.
- This program performs NO outbound "writes" that change panel entities/states.
  It only sends the registered request: ("control","get_version_info").

How it works:
- Session: TCP + HELLO + framed crypto + recv pump
- Elk: dispatcher + features + outbound request registry + event stamping/queue
- Feature: control registers handler + request builder for ("control","get_version_info")

Environment variables (optional):
- ELKE27_HOST
- ELKE27_PORT (default 2101)
- ELKE27_IDENTITY (default "elk-client")
- ELKE27_LINK_KEY_HEX  (required if not passed via args)

Example:
  ELKE27_HOST=192.168.1.50 ELKE27_LINK_KEY_HEX=... python examples/e27_live_version_info.py
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Optional

from elke27_lib.session import Session, SessionConfig
from elke27_lib.elk import Elk


LOG = logging.getLogger(__name__)

ROUTE_CONTROL_GET_VERSION_INFO = ("control", "get_version_info")


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def main() -> int:
    parser = argparse.ArgumentParser(description="E27 live test: control.get_version_info")
    parser.add_argument("--host", default=_env("ELKE27_HOST"), help="Panel IP/host (or ELKE27_HOST)")
    parser.add_argument("--port", type=int, default=int(_env("ELKE27_PORT", "2101")), help="Panel port (default 2101)")
    parser.add_argument("--identity", default=_env("ELKE27_IDENTITY", "elk-client"), help="Client identity string")
    parser.add_argument("--link-key-hex", default=_env("ELKE27_LINK_KEY_HEX"), help="Provisioned link key hex")
    parser.add_argument("--timeout-s", type=float, default=10.0, help="Overall time to wait for version info")
    parser.add_argument("--log-level", default=_env("LOG_LEVEL", "INFO"), help="DEBUG/INFO/WARNING/ERROR")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO), format="%(message)s")

    if not args.host:
        print("Missing --host (or ELKE27_HOST)")
        return 2
    if not args.link_key_hex:
        print("Missing --link-key-hex (or ELKE27_LINK_KEY_HEX)")
        return 2

    # 1) Create Session (transport + HELLO + crypto framing)
    cfg = SessionConfig(host=args.host, port=args.port)
    session = Session(cfg, identity=args.identity, link_key_hex=args.link_key_hex)

    # 2) Create Elk kernel (loads DEFAULT_FEATURES: control + area, etc.)
    elk = Elk(session=session)

    # 3) Connect (HELLO runs inside Session.connect)
    LOG.info("Connecting to %s:%s ...", args.host, args.port)
    info = session.connect()
    LOG.info("HELLO complete: session_id=%s", info.session_id)

    # 4) Send request via Elk request registry
    LOG.info("Sending request: %r", ROUTE_CTRL_GET_VERSION_INFO)
    seq = elk.request(ROUTE_CONTROL_GET_VERSION_INFO)
    LOG.info("Sent seq=%s", seq)

    # 5) Pump until we see a PanelVersionInfoUpdated or ApiError for this request,
    #    or until timeout.
    deadline = time.monotonic() + float(args.timeout_s)

    got_any_response = False
    while time.monotonic() < deadline:
        # Pump one message (dispatch happens via session.on_message -> elk._on_message)
        try:
            session.pump_once(timeout_s=0.5)
        except TimeoutError:
            pass
        except Exception as e:
            LOG.error("Session pump failed: %s: %s", type(e).__name__, e)
            break

        # Drain and display events
        events = elk.drain_events()
        for evt in events:
            # If your events have kind fields, we can filter by kind.
            # We intentionally print everything for first live test visibility.
            print(evt)

            if getattr(evt, "seq", None) == seq:
                got_any_response = True
                # Stop as soon as we see either version info or api error for this seq
                if getattr(evt, "kind", "") in ("panel_version_info_updated", "api_error"):
                    LOG.info("Got terminal event for seq=%s: kind=%s", seq, getattr(evt, "kind", ""))
                    # Print current PanelState snapshot
                    print("\nPanelState.panel:")
                    print(f"  session_id = {elk.state.panel.session_id}")
                    print(f"  model      = {elk.state.panel.model}")
                    print(f"  firmware   = {elk.state.panel.firmware}")
                    print(f"  serial     = {elk.state.panel.serial}")
                    session.close()
                    return 0

    # Timed out or exited loop
    if not got_any_response:
        LOG.warning("No response correlated to seq=%s within %.1fs", seq, args.timeout_s)
    else:
        LOG.warning("Did not observe terminal event kind for seq=%s within %.1fs", seq, args.timeout_s)

    print("\nPanelState.panel (best-effort):")
    print(f"  session_id = {elk.state.panel.session_id}")
    print(f"  model      = {elk.state.panel.model}")
    print(f"  firmware   = {elk.state.panel.firmware}")
    print(f"  serial     = {elk.state.panel.serial}")

    try:
        session.close()
    except Exception:
        pass
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
