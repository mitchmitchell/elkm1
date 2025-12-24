#!/usr/bin/env python3
"""
E27 smoke test tool

This script exercises the E27 panel handshake and (optionally) a few basic API calls.

Important:
- API_LINK is clear + UNFRAMED (panel associates app to panel; like "wiring a keypad").
- HELLO is clear + UNFRAMED (done on each new TCP connection).
- After HELLO, traffic is FRAMED + ENCRYPTED (schema-0).

This file has been updated to use the *current* linking API:
    from elke27_lib.linking import E27Identity, perform_api_link

Per request:
- No legacy fallback paths.
- Do not modify session.py or linking.py.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable

from elke27_lib.linking import E27Identity, perform_api_link
from elke27_lib.framing import DeframeState, deframe_feed, frame_build
from elke27_lib.presentation import (
    decrypt_schema0_envelope,
    encrypt_schema0_envelope,
)

# ----------------------------
# Event helpers (JSONL-ish)
# ----------------------------


def _emit_event(events: list[dict[str, Any]], event: str, *args: Any, **kwargs: Any) -> None:
    obj = {"event": event, "args": list(args), "kwargs": dict(kwargs)}
    events.append(obj)
    print(json.dumps(obj, indent=2, sort_keys=True))


def _emit_exception(events: list[dict[str, Any]], exc: BaseException) -> None:
    obj = {
        "event": "exception",
        "type": type(exc).__name__,
        "message": str(exc),
    }
    events.append(obj)
    print(json.dumps(obj, indent=2, sort_keys=True))


# ----------------------------
# Socket helpers
# ----------------------------


def _recv_some(sock: socket.socket, max_bytes: int = 4096) -> bytes:
    return sock.recv(max_bytes)


def _send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(data)


def _recv_unframed_json(
    sock: socket.socket,
    *,
    timeout_s: float,
    expect_key: str | None = None,
    log_raw: bool = False,
) -> dict[str, Any]:
    sock.settimeout(timeout_s)

    # The panel sometimes sends two JSON objects back-to-back without a delimiter.
    # We'll read until we can parse *at least* one object; if expect_key is set,
    # we keep reading until we see it in the first parsed object.
    buf = bytearray()
    while True:
        chunk = _recv_some(sock)
        if not chunk:
            raise TimeoutError("socket closed while waiting for unframed JSON")
        buf.extend(chunk)

        if log_raw:
            print(f"<< raw recv {len(chunk)} bytes: {chunk.hex().upper()}")

        # Try parse from the start; accept the first object
        try:
            text = buf.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue

        # Try progressively: json.loads requires full object
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                if expect_key is None or expect_key in obj:
                    return obj
        except json.JSONDecodeError:
            # Not a single complete JSON value yet (or multiple concatenated)
            pass

        # If multiple concatenated JSON objects exist, parse the first one with a simple scanner.
        # This is intentionally conservative and only supports objects/arrays; good enough for ELKWC2017/LOCAL.
        first = _extract_first_json_value(buf)
        if first is None:
            continue
        try:
            obj = json.loads(first.decode("utf-8"))
        except Exception:
            continue
        if isinstance(obj, dict):
            if expect_key is None or expect_key in obj:
                return obj


def _extract_first_json_value(buf: bytes | bytearray) -> bytes | None:
    """
    Return the first complete JSON value (object/array/string/number/true/false/null) from buf,
    if present, else None.

    For this tool we mostly need to handle concatenated JSON objects from the panel.
    """
    if not buf:
        return None

    # Skip leading whitespace
    i = 0
    n = len(buf)
    while i < n and buf[i] in b" \t\r\n":
        i += 1
    if i >= n:
        return None

    start = i
    c = buf[i]

    # Object / Array scanning with brace depth and string handling
    if c in (ord("{"), ord("[")):
        depth = 0
        in_str = False
        esc = False
        while i < n:
            ch = buf[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == ord("\\"):
                    esc = True
                elif ch == ord('"'):
                    in_str = False
            else:
                if ch == ord('"'):
                    in_str = True
                elif ch in (ord("{"), ord("[")):
                    depth += 1
                elif ch in (ord("}"), ord("]")):
                    depth -= 1
                    if depth == 0:
                        return bytes(buf[start : i + 1])
            i += 1
        return None

    # For other JSON types, fall back to trying full decode (handled elsewhere)
    return None


def _deframe_one(
    sock: socket.socket,
    st: DeframeState,
    *,
    timeout_s: float,
    log_raw: bool = False,
) -> bytes:
    """
    Receive framed bytes until one good frame arrives, return frame_no_crc bytes:
      [protocol][len_lo][len_hi][ciphertext...]
    """
    sock.settimeout(timeout_s)

    while True:
        chunk = _recv_some(sock)
        if not chunk:
            raise TimeoutError("socket closed while waiting for framed data")
        if log_raw:
            print(f"<< raw recv {len(chunk)} bytes: {chunk.hex().upper()}")

        results = deframe_feed(st, chunk)
        for r in results:
            # framing.DeframeResult supports .ok and .frame_no_crc in the refactor
            if getattr(r, "ok", False) and getattr(r, "frame_no_crc", None) is not None:
                return r.frame_no_crc
            err = getattr(r, "error", None)
            if err:
                # keep scanning; tests expect we can resync
                if log_raw:
                    print(f"<< deframe error: {err}")


# ----------------------------
# Message builders (minimal)
# ----------------------------


def _build_authenticate(*, seq: int, pin: int) -> dict[str, Any]:
    return {"authenticate": {"seq": seq, "pin": int(pin)}}


def _build_area_get_status(*, seq: int, session_id: int, area_id: int) -> dict[str, Any]:
    return {"seq": seq, "session_id": session_id, "area": {"get_status": {"area_id": int(area_id)}}}


# ----------------------------
# Main
# ----------------------------


@dataclass
class Args:
    host: str
    port: int
    mn: str
    sn: str
    access_code: str
    pass_phrase: str
    pin: int
    timeout: float
    log_raw: bool
    do_area_status: bool
    area_id: int
    fwver: str
    hwver: str
    osver: str


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="e27_smoketest")

    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=2101)

    p.add_argument("--mn", default=(os.environ.get("E27_MN") or "").strip(), help="Module number (MN)")
    p.add_argument("--sn", default="A4FC143918A4", help="Serial number (SN) / app identity")
    p.add_argument("--access-code", default=(os.environ.get("E27_ACCESS_CODE") or "").strip())
    p.add_argument("--pass-phrase", default=(os.environ.get("E27_PASSPHRASE") or "").strip())

    p.add_argument("--pin", type=int, default=4231)

    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--log-raw", action="store_true")

    p.add_argument("--do-area-status", action="store_true")
    p.add_argument("--area-id", type=int, default=1)

    p.add_argument("--fwver", default="0.0.1")
    p.add_argument("--hwver", default="0.0.1")
    p.add_argument("--osver", default="0.0.1")

    ns = p.parse_args(argv)

    args = Args(
        host=ns.host,
        port=ns.port,
        mn=str(ns.mn),
        sn=str(ns.sn),
        access_code=str(ns.access_code),
        pass_phrase=str(ns.pass_phrase),
        pin=int(ns.pin),
        timeout=float(ns.timeout),
        log_raw=bool(ns.log_raw),
        do_area_status=bool(ns.do_area_status),
        area_id=int(ns.area_id),
        fwver=str(ns.fwver),
        hwver=str(ns.hwver),
        osver=str(ns.osver),
    )

    events: list[dict[str, Any]] = []

    if not args.mn:
        _emit_event(events, "error", "Missing MN (--mn or E27_MN).")
        return 2
    if not args.access_code or not args.pass_phrase:
        _emit_event(events, "error", "Missing credentials: --access-code/--pass-phrase (or env E27_ACCESS_CODE/E27_PASSPHRASE).")
        return 2

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"Connecting to {args.host}:{args.port} ...")
        sock.settimeout(args.timeout)
        sock.connect((args.host, args.port))
        print("Connected.")

        print("Waiting for discovery hello (ELKWC2017)...")
        discovery = _recv_unframed_json(sock, timeout_s=args.timeout, expect_key="ELKWC2017", log_raw=args.log_raw)
        discovery_nonce = discovery.get("nonce")
        if not isinstance(discovery_nonce, str) or not discovery_nonce:
            raise RuntimeError("Discovery hello missing nonce")
        print(f"Discovery nonce: {discovery_nonce}")

        # ---- api_link (clear, UNFRAMED) ----
        print("Sending api_link (clear, UNFRAMED)...")
        identity = E27Identity(
            mn=str(args.mn),
            sn=str(args.sn),
            fwver=args.fwver,
            hwver=args.hwver,
            osver=args.osver,
        )
        try:
            link_key_hex, link_hmac_hex = perform_api_link(
                sock=sock,
                identity=identity,
                access_code=args.access_code,
                passphrase=args.pass_phrase,
                mn_for_hash=str(args.mn),
                discovery_nonce=discovery_nonce,
                timeout_s=args.timeout,
                log_raw=args.log_raw,
            )
        except Exception as e:
            _emit_event(events, "error", f"API_LINK failed: {e}")
            _emit_exception(events, e)
            return 2

        print("api_link response decrypted OK.")
        print(f"  linkkey length: {len(link_key_hex)} hex chars")
        print(f"  linkhmac length: {len(link_hmac_hex)} hex chars")
        link_key = bytes.fromhex(link_key_hex)
        link_hmac = bytes.fromhex(link_hmac_hex)

        # ---- hello (clear, UNFRAMED) ----
        print("Sending hello (clear, UNFRAMED)...")
        hello_req = {"seq": 110, "hello": {"mn": str(args.mn), "sn": str(args.sn), "fwver": args.fwver, "hwver": args.hwver, "osver": args.osver}}
        hello_bytes = json.dumps(hello_req, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if args.log_raw:
            print(f">> hello JSON: {hello_bytes.decode('utf-8', errors='replace')}")
        _send(sock, hello_bytes)

        print("Waiting for hello response (clear JSON with encrypted sk/shm)...")
        hello_resp = _recv_unframed_json(sock, timeout_s=args.timeout, expect_key="hello", log_raw=args.log_raw)
        hello_obj = hello_resp.get("hello") if isinstance(hello_resp, dict) else None
        if not isinstance(hello_obj, dict) or int(hello_obj.get("error_code", 1)) != 0:
            raise RuntimeError(f"HELLO failed: {hello_resp}")

        session_id = int(hello_obj["session_id"])
        session_key_hex = str(hello_obj["sk"])
        session_hmac_hex = str(hello_obj["shm"])
        session_key = bytes.fromhex(session_key_hex)
        session_hmac = bytes.fromhex(session_hmac_hex)

        print("hello response processed OK.")
        print(f"  sessionKey length: {len(session_key_hex)} hex chars")
        print(f"  hmacKey length:    {len(session_hmac_hex)} hex chars")

        # ---- authenticate (FRAMED + ENCRYPTED schema-0) ----
        print("Sending encrypted authenticate (schema-0)...")
        auth_obj = _build_authenticate(seq=110, pin=args.pin)
        auth_payload = json.dumps(auth_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        proto, ciphertext = encrypt_schema0_envelope(payload=auth_payload, session_key=session_key)
        framed = frame_build(protocol_byte=proto, data_frame=ciphertext)
        if args.log_raw:
            print(f">> cmd JSON: {json.dumps(auth_obj, indent=2, sort_keys=True)}")
            print(f">> protocol: 0x{proto:02X}")
            print(f">> data_frame (ciphertext) {len(ciphertext)} bytes: {ciphertext.hex().upper()}")
            print(f">> framed bytes: {framed.hex().upper()}")
        _send(sock, framed)

        print("Waiting for encrypted response...")
        st = DeframeState()
        frame_no_crc = _deframe_one(sock, st, timeout_s=args.timeout, log_raw=args.log_raw)
        # frame_no_crc = protocol + len_lo + len_hi + ciphertext
        resp_proto = frame_no_crc[0]
        resp_cipher = frame_no_crc[3:]
        resp_plain = decrypt_schema0_envelope(ciphertext=resp_cipher, session_key=session_key)
        resp_json = json.loads(resp_plain.decode("utf-8"))

        print("=== Decrypted response JSON ===")
        print(json.dumps(resp_json, indent=2, sort_keys=True))

        # ---- optional: area.get_status ----
        if args.do_area_status:
            print("Sending encrypted area.get_status (schema-0)...")
            area_obj = _build_area_get_status(seq=111, session_id=session_id, area_id=args.area_id)
            area_payload = json.dumps(area_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            proto2, cipher2 = encrypt_schema0_envelope(payload=area_payload, session_key=session_key)
            framed2 = frame_build(protocol_byte=proto2, data_frame=cipher2)
            if args.log_raw:
                print(f">> area cmd JSON: {json.dumps(area_obj, separators=(',', ':'), ensure_ascii=False)}")
                print(f">> protocol: 0x{proto2:02X}")
                print(f">> framed bytes: {framed2.hex().upper()}")
            _send(sock, framed2)

            print("Waiting for encrypted response...")
            frame_no_crc2 = _deframe_one(sock, st, timeout_s=args.timeout, log_raw=args.log_raw)
            resp_cipher2 = frame_no_crc2[3:]
            resp_plain2 = decrypt_schema0_envelope(ciphertext=resp_cipher2, session_key=session_key)
            resp_json2 = json.loads(resp_plain2.decode("utf-8"))

            print("=== Decrypted area.get_status response JSON ===")
            print(json.dumps(resp_json2, indent=2, sort_keys=True))

        _emit_event(events, "ok", "smoketest completed")
        return 0

    except KeyboardInterrupt:
        _emit_event(events, "error", "Interrupted (Ctrl-C).")
        return 130
    except Exception as e:
        _emit_event(events, "error", str(e))
        _emit_exception(events, e)
        return 2
    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
