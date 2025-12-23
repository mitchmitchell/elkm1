#!/usr/bin/env python3
"""
E27 live smoketest (minimal harness)

Proves end-to-end against a real panel:
  - Receive discovery hello (clear JSON) and extract panel nonce
  - Send api_link (clear JSON, UNFRAMED)
  - Receive api_link response (FRAMED + schema-0 encrypted), decrypt with tempkey, extract linkkey/linkhmac
  - Send hello (clear JSON, UNFRAMED)
  - Receive hello response (clear JSON with encrypted sk/shm), decrypt sk/shm with linkkey to get sessionKey/hmacKey
  - Send one encrypted command (authenticate), receive/decrypt response and print JSON
  - Optionally send area.get_status after authenticate

Notes:
  - Cleartext JSON messages are NOT framed:
      discovery hello, api_link request, hello request, hello response
  - Encrypted schema-0 messages ARE framed:
      api_link response, authenticate, all subsequent encrypted commands/responses
  - Application layer prepends one byte (ack/head) before the JSON inside the decrypted payload.
    Node-RED strips this in Application Layer; we do the same here.
"""

from __future__ import annotations

import argparse
import json
import socket
import os
import sys
import time
from typing import Any, Optional

from elkm1.elke27_lib.framing import DeframeState, deframe_feed, frame_build
from elkm1.elke27_lib.linking import (
    parse_concatenated_json_objects,
    prepare_api_link,
    build_hello_request_json,
)
from elkm1.elke27_lib.presentation import unpack_inbound, pack_outbound_schema0
from elkm1.elke27_lib.encryption import decrypt_hello_field


DEFAULT_PORT = 2101


def _hex(b: bytes) -> str:
    return b.hex().upper()


def _pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def _bytes_to_hex_upper(b: bytes) -> str:
    return b.hex().upper()


def recv_some(sock: socket.socket, size: int) -> bytes:
    try:
        return sock.recv(size)
    except socket.timeout:
        return b""


def strip_ack_and_parse_json(app_bytes: bytes, *, label: str, log_raw: bool) -> tuple[int, Any]:
    """
    app_bytes = ack/head (1 byte) + JSON bytes

    Returns:
      (acknack, obj)

    Raises:
      ValueError on parse failure
    """
    if not app_bytes:
        raise ValueError(f"{label}: empty app_bytes")

    acknack = app_bytes[0] & 0xFF
    json_only = app_bytes[1:]

    if log_raw:
        print(f"<< ack/nack byte: 0x{acknack:X}".lower())

    try:
        obj = json.loads(json_only.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"{label}: JSON decode failed: {e}") from e

    return acknack, obj


def wait_for_discovery(sock: socket.socket, *, recv_chunk: int, timeout: float, log_raw: bool) -> dict[str, Any]:
    print("Waiting for discovery hello (ELKWC2017)...")
    t0 = time.time()
    buf = bytearray()

    while (time.time() - t0) < timeout:
        chunk = recv_some(sock, recv_chunk)
        if not chunk:
            continue

        buf.extend(chunk)
        if log_raw:
            print(f"<< raw recv {len(chunk)} bytes: {_hex(chunk)}")

        # Discovery often arrives as concatenated JSON objects (e.g., ELKWC2017 + LOCAL).
        # Parse what we have each time and look for the one with ELKWC2017.
        try:
            parts = parse_concatenated_json_objects(buf.decode("utf-8", errors="ignore"))
        except Exception:
            continue

        for p in parts:
            try:
                obj = json.loads(p)
            except Exception:
                continue
            if "ELKWC2017" in obj:
                return obj

    raise TimeoutError("Timed out waiting for discovery hello (ELKWC2017).")


def wait_for_api_link_response(
    sock: socket.socket,
    *,
    deframe_state: DeframeState,
    tempkey_hex: str,
    recv_chunk: int,
    timeout: float,
    log_raw: bool,
) -> tuple[int, dict[str, Any]]:
    print("Waiting for api_link response (encrypted, schema-0)...")
    t0 = time.time()

    while (time.time() - t0) < timeout:
        chunk = recv_some(sock, recv_chunk)
        if not chunk:
            continue

        if log_raw:
            print(f"<< raw recv {len(chunk)} bytes: {_hex(chunk)}")

        results = deframe_feed(deframe_state, chunk)
        for r in results:
            if not r.ok:
                print(f"!! deframe error: {r.error}")
                continue

            frame_no_crc = r.frame_no_crc or b""
            if log_raw:
                print(f"<< frame_no_crc: {_hex(frame_no_crc)}")

            meta, app_bytes = unpack_inbound(
                frame_no_crc=frame_no_crc,
                tempkey_hex=tempkey_hex,
                session_key_hex=None,
            )

            if log_raw:
                print(f"<< decrypted JSON bytes: {_hex(app_bytes)}")

            try:
                _, obj = strip_ack_and_parse_json(app_bytes, label="api_link", log_raw=log_raw)
            except Exception as e:
                print(f"!! {e}")
                continue

            return (app_bytes[0] & 0xFF), obj

    raise TimeoutError("Timed out waiting for decrypted api_link response / link key.")


def wait_for_hello_response(
    sock: socket.socket,
    *,
    recv_chunk: int,
    timeout: float,
    log_raw: bool,
) -> dict[str, Any]:
    print("Waiting for hello response (clear JSON with encrypted sk/shm)...")
    t0 = time.time()
    buf = bytearray()

    while (time.time() - t0) < timeout:
        chunk = recv_some(sock, recv_chunk)
        if not chunk:
            continue

        buf.extend(chunk)
        if log_raw:
            print(f"<< raw recv {len(chunk)} bytes: {_hex(chunk)}")

        # Hello response is clear JSON, and can also arrive concatenated.
        try:
            parts = parse_concatenated_json_objects(buf.decode("utf-8", errors="ignore"))
        except Exception:
            continue

        for p in parts:
            try:
                obj = json.loads(p)
            except Exception:
                continue
            if "hello" in obj:
                return obj

    raise TimeoutError("Timed out waiting for hello response.")


def wait_for_encrypted_response(
    sock: socket.socket,
    *,
    deframe_state: DeframeState,
    session_key_hex: str,
    recv_chunk: int,
    timeout: float,
    log_raw: bool,
    label: str,
) -> tuple[int, dict[str, Any]]:
    print("Waiting for encrypted response...")
    t0 = time.time()

    while (time.time() - t0) < timeout:
        chunk = recv_some(sock, recv_chunk)
        if not chunk:
            continue

        if log_raw:
            print(f"<< raw recv {len(chunk)} bytes: {_hex(chunk)}")

        results = deframe_feed(deframe_state, chunk)
        for r in results:
            if not r.ok:
                print(f"!! deframe error: {r.error}")
                continue

            frame_no_crc = r.frame_no_crc or b""
            meta, app_bytes = unpack_inbound(
                frame_no_crc=frame_no_crc,
                tempkey_hex=None,
                session_key_hex=session_key_hex,
            )

            try:
                ack, obj = strip_ack_and_parse_json(app_bytes, label=label, log_raw=log_raw)
            except Exception as e:
                print(f"!! {e}")
                if log_raw:
                    print(f"!! decrypted bytes: {_hex(app_bytes)}")
                continue

            return ack, obj

    raise TimeoutError(f"Timed out waiting for encrypted response: {label}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="Panel IP/hostname")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="Panel port (default 2101)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Timeout seconds per wait phase")
    ap.add_argument("--recv-chunk", type=int, default=4096, help="Socket recv() size")
    ap.add_argument("--log-raw", action="store_true", help="Print raw hex of inbound/outbound")
    ap.add_argument("--pin", type=int, default=4231, help="PIN for authenticate")
    ap.add_argument("--do-area-status", action="store_true", help="After authenticate, send area.get_status area_id=1")
    args = ap.parse_args()

    access_code = (os.environ.get("E27_ACCESS_CODE") or "12345678").strip()
    passphrase = (os.environ.get("E27_PASSPHRASE") or "my pass phrase").strip()
    mn = (os.environ.get("E27_MN") or "100").strip()

    if not access_code or not passphrase or not mn:
        print("ERROR: E27_ACCESS_CODE, E27_PASSPHRASE, E27_MN must be set in environment.", file=sys.stderr)
        return 2

    print(f"Connecting to {args.host}:{args.port} ...")
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        sock.settimeout(0.25)
        print("Connected.")

        # 1) discovery hello
        disc = wait_for_discovery(sock, recv_chunk=args.recv_chunk, timeout=args.timeout, log_raw=args.log_raw)
        nonce = str(disc.get("nonce", "")).strip().lower()
        if not nonce:
            print(f"ERROR: discovery did not include nonce: {disc}", file=sys.stderr)
            return 1
        print(f"Discovery nonce: {nonce}")

        # 2) api_link clear (UNFRAMED)
        linkprep = prepare_api_link(
            panel_host=args.host,
            access_code=access_code,
            passphrase=passphrase,
            mn=mn,
            panel_nonce_hex=nonce,
        )

        print("Sending api_link (clear, UNFRAMED)...")
        if args.log_raw:
            print(f">> api_link JSON: {linkprep.request_json_bytes.decode('utf-8', errors='replace')}")
        sock.sendall(linkprep.request_json_bytes)

        # 3) api_link response framed + schema-0 encrypted (decrypt with tempkey)
        deframe_state = DeframeState()
        _, api_link_obj = wait_for_api_link_response(
            sock,
            deframe_state=deframe_state,
            tempkey_hex=linkprep.tempkey_hex,
            recv_chunk=args.recv_chunk,
            timeout=args.timeout,
            log_raw=args.log_raw,
        )

        print("api_link response decrypted OK.")
        try:
            api_link = api_link_obj["api_link"]
            linkkey_hex = str(api_link["enc"]).strip()
            linkhmac_hex = str(api_link["hmac"]).strip()
        except Exception as e:
            print(f"ERROR: api_link response missing fields: {e}", file=sys.stderr)
            print(_pretty_json(api_link_obj))
            return 1

        print(f"  linkkey length: {len(linkkey_hex)} hex chars")
        print(f"  linkhmac length: {len(linkhmac_hex)} hex chars")

        # 4) hello clear (UNFRAMED)
        hello_req = build_hello_request_json(
            mn=linkprep.mn,
            sn=linkprep.sn,
            fwver=linkprep.fwver,
            hwver=linkprep.hwver,
            osver=linkprep.osver,
            json_seq=110,
        )
        print("Sending hello (clear, UNFRAMED)...")
        if args.log_raw:
            print(f">> hello JSON: {hello_req.decode('utf-8', errors='replace')}")
        sock.sendall(hello_req)

        # 5) hello response clear JSON; decrypt sk/shm fields with linkkey
        hello_obj = wait_for_hello_response(sock, recv_chunk=args.recv_chunk, timeout=args.timeout, log_raw=args.log_raw)

        try:
            hello = hello_obj["hello"]
            session_id_unauth = int(hello["session_id"])
            sk_hex = str(hello["sk"]).strip()
            shm_hex = str(hello["shm"]).strip()
        except Exception as e:
            print(f"ERROR: hello response missing fields: {e}", file=sys.stderr)
            print(_pretty_json(hello_obj))
            return 1

        try:
            session_key_bytes = decrypt_hello_field(linkkey_hex=linkkey_hex, field_hex=sk_hex)
            hmac_key_bytes = decrypt_hello_field(linkkey_hex=linkkey_hex, field_hex=shm_hex)
        except Exception as e:
            print(f"ERROR: decrypting hello keys failed: {e}", file=sys.stderr)
            return 1

        session_key_hex = _bytes_to_hex_upper(session_key_bytes)
        hmac_key_hex = _bytes_to_hex_upper(hmac_key_bytes)

        print("hello response processed OK.")
        print(f"  sessionKey length: {len(session_key_hex)} hex chars")
        print(f"  hmacKey length:    {len(hmac_key_hex)} hex chars")

        # 6) send encrypted authenticate (schema-0)
        auth_cmd = {"authenticate": {"seq": 110, "pin": int(args.pin)}}
        auth_cmd_bytes = json.dumps(auth_cmd, separators=(",", ":")).encode("utf-8")

        protocol_byte, data_frame = pack_outbound_schema0(
            json_bytes=auth_cmd_bytes,
            session_key_hex=session_key_hex,
            src=1,
            dest=0,
            seq=1234,
            head=0,
        )
        wire = frame_build(protocol_byte=protocol_byte, data_frame=data_frame)

        print("Sending encrypted authenticate (schema-0)...")
        if args.log_raw:
            print(f">> cmd JSON: {auth_cmd_bytes.decode('utf-8', errors='replace')}")
            print(f">> protocol: 0x{protocol_byte:02X}")
            print(f">> data_frame (ciphertext) {len(data_frame)} bytes: {_hex(data_frame)}")
            print(f">> framed bytes: {_hex(wire)}")
        sock.sendall(wire)

        ack, auth_resp = wait_for_encrypted_response(
            sock,
            deframe_state=deframe_state,
            session_key_hex=session_key_hex,
            recv_chunk=args.recv_chunk,
            timeout=args.timeout,
            log_raw=args.log_raw,
            label="authenticate",
        )

        print("=== Decrypted response JSON ===")
        print(_pretty_json(auth_resp))

        # Optional: area.get_status
        if args.do_area_status:
            try:
                session_id = int(auth_resp["authenticate"]["session_id"])
            except Exception as e:
                print(f"ERROR: could not extract session_id from authenticate response: {e}", file=sys.stderr)
                return 1

            area_cmd = {
                "seq": 111,
                "session_id": session_id,
                "area": {
                    "get_status": {
                        "area_id": 1
                    }
                },
            }
            area_cmd_bytes = json.dumps(area_cmd, separators=(",", ":")).encode("utf-8")

            protocol_byte2, data_frame2 = pack_outbound_schema0(
                json_bytes=area_cmd_bytes,
                session_key_hex=session_key_hex,
                src=1,
                dest=0,
                seq=1235,
                head=0,
            )
            wire2 = frame_build(protocol_byte=protocol_byte2, data_frame=data_frame2)

            print("Sending encrypted area.get_status (schema-0)...")
            if args.log_raw:
                print(f">> area cmd JSON: {area_cmd_bytes.decode('utf-8', errors='replace')}")
                print(f">> protocol: 0x{protocol_byte2:02X}")
                print(f">> framed bytes: {_hex(wire2)}")
            sock.sendall(wire2)

            _, area_resp = wait_for_encrypted_response(
                sock,
                deframe_state=deframe_state,
                session_key_hex=session_key_hex,
                recv_chunk=args.recv_chunk,
                timeout=args.timeout,
                log_raw=args.log_raw,
                label="area.get_status",
            )

            print("=== Decrypted area.get_status response JSON ===")
            print(_pretty_json(area_resp))

        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
