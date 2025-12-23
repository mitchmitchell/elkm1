from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from elkm1.elke27_lib.errors import (
    E27Error,
    E27ErrorContext,
    E27ProvisioningRequired,
    E27ProvisioningTimeout,
    E27ProtocolError,
    E27TransportError,
)
from elkm1.elke27_lib.linking import (
    API_LINK_IV,
    E27Identity,
    LinkCredentials,
    build_api_link_request,
    derive_pass_tempkey_with_cnonce,
    parse_api_link_response_json,
    recv_cleartext_json_objects,
    send_unframed_json,
)
from elkm1.elke27_lib.hello import perform_hello

# NOTE: Replace these imports with your real modules/functions
# from elkm1.elke27_lib.framing import E27Deframer
# from elkm1.elke27_lib.presentation import decrypt_schema0_payload, decrypt_api_link_response


def _env_required(name: str) -> str:
    v = (os.environ.get(name) or "").strip()
    if not v:
        raise SystemExit(f"Missing required environment variable: {name}")
    return v


def _connect(host: str, port: int, timeout_s: float = 5.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    s.connect((host, port))
    return s


def _recv_some(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    sock.settimeout(timeout_s)
    return sock.recv(4096)


def _parse_discovery_nonce(sock: socket.socket, timeout_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    buf = bytearray()
    sock.settimeout(1.0)
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise E27TransportError("Socket closed during discovery.", context=E27ErrorContext(phase="discovery"))
        buf.extend(chunk)
        s = buf.decode("utf-8", errors="ignore")
        if "ELKWC2017" not in s:
            continue
        # reuse cleartext parser from linking module
        objs = []
        try:
            objs = json.loads(buf.decode("utf-8", errors="replace").strip().split("}{")[0] + "}")  # fallback
        except Exception:
            pass
        # Prefer robust parser:
        from elkm1.elke27_lib.linking import recv_cleartext_json_objects_from_bytes
        for obj in recv_cleartext_json_objects_from_bytes(bytes(buf)):
            if "nonce" in obj:
                return str(obj["nonce"])
    raise E27ProvisioningTimeout(
        "Timed out waiting for discovery nonce.",
        context=E27ErrorContext(phase="discovery"),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=2101)
    ap.add_argument("--do-area-status", action="store_true")
    ap.add_argument("--pin", type=int, default=4231)
    ap.add_argument("--log-raw", action="store_true")
    args = ap.parse_args()

    access_code = _env_required("E27_ACCESS_CODE")
    passphrase = _env_required("E27_PASSPHRASE")
    mn = _env_required("E27_MN")

    # Identity fields: keep same defaults you used in smoketest
    sn = "A4FC143918A4"  # you later decided to derive from MAC; keep as-is here
    identity = E27Identity(mn=mn, sn=sn, fwver="0.0.1", hwver="0.0.1", osver="0.0.1")

    print(f"Connecting to {args.host}:{args.port} ...")
    sock = _connect(args.host, args.port, timeout_s=5.0)
    print("Connected.")

    # 1) discovery (clear)
    print("Waiting for discovery hello (ELKWC2017)...")
    nonce = _parse_discovery_nonce(sock, timeout_s=10.0)
    if args.log_raw:
        print(f"Discovery nonce: {nonce}")
    else:
        print("Discovery nonce received.")

    # 2) api_link request (clear/unframed) + response (framed/encrypted)
    #    NOTE: per DDR-0020, wrong creds == silent timeout; treat as provisioning timeout.
    # Derivation must match what you proved in Node-RED:
    cnonce = os.urandom(20).hex().lower()
    pass8, tempkey_hex = derive_pass_tempkey_with_cnonce(
        access_code=access_code,
        passphrase=passphrase,
        nonce=nonce,
        cnonce=cnonce,
        mn=mn,
        sn=identity.sn,
    )
    api_link_json = build_api_link_request(seq=110, identity=identity, pass_hex8=pass8, cnonce_hex=cnonce)

    print("Sending api_link (clear, UNFRAMED)...")
    if args.log_raw:
        print(f">> api_link JSON: {api_link_json}")
    send_unframed_json(sock, api_link_json)

    print("Waiting for api_link response (encrypted, schema-0)...")
    # --- RECEIVE + DECRYPT api_link response ---
    # Replace this block with your working deframer + schema0 decrypt.
    # Expected output: decrypted bytes that start with ack byte then JSON bytes.
    try:
        raw = _recv_some(sock, timeout_s=5.0)
    except socket.timeout as e:
        raise E27ProvisioningTimeout(
            "No response to api_link (panel may silently ignore incorrect credentials).",
            context=E27ErrorContext(host=args.host, port=args.port, phase="api_link"),
            cause=e,
        )

    if args.log_raw:
        print(f"<< raw recv {len(raw)} bytes: {raw.hex().upper()}")

    # TODO: plug in your real stream deframer here
    # frame_no_crc = deframer.consume(raw) -> bytes (protocol+len+payload without crc)
    # decrypted = presentation.decrypt_schema0(frame_no_crc, key=tempkey_hex, iv=API_LINK_IV) -> bytes
    # For now, require you to wire these two functions to match your current codebase.
    from elkm1.elke27_lib.tools.e27_smoketest import _deframe_one_frame_from_bytes, _decrypt_schema0_frame  # type: ignore

    frame_no_crc = _deframe_one_frame_from_bytes(raw)
    decrypted = _decrypt_schema0_frame(frame_no_crc, key_hex=tempkey_hex)

    if args.log_raw:
        print(f"<< decrypted JSON bytes: {decrypted.hex().upper()}")

    if not decrypted:
        raise E27ProtocolError("api_link decrypt returned empty plaintext.", context=E27ErrorContext(phase="api_link_decrypt"))

    ack = decrypted[0]
    json_bytes = decrypted[1:]
    if args.log_raw:
        print(f"<< ack/nack byte: 0x{ack:02x}")

    try:
        obj = json.loads(json_bytes.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise E27ProtocolError(
            f"JSON decode failed after api_link decrypt: {e}",
            context=E27ErrorContext(phase="api_link_json_decode"),
            cause=e,
        )

    creds = parse_api_link_response_json(obj)
    print("api_link response decrypted OK.")
    print(f"  linkkey length: {len(creds.linkkey_hex)} hex chars")
    print(f"  linkhmac length: {len(creds.linkhmac_hex)} hex chars")

    # 3) hello (clear/unframed) + decrypt session keys
    print("Sending hello (clear, UNFRAMED)...")
    keys = perform_hello(sock=sock, identity=identity, linkkey_hex=creds.linkkey_hex, seq=110, timeout_s=5.0)
    print("hello response processed OK.")
    print(f"  sessionKey length: {len(keys.session_key_hex)} hex chars")
    print(f"  hmacKey length:    {len(keys.hmac_key_hex)} hex chars")

    # 4) authenticate + sample call(s)
    # For step 2 we stop here (you already have working auth/call path);
    # step 3/4 will move encrypted call into session.py and then HA integration.
    if args.do_area_status:
        print("NOTE: Encrypted calls remain in the original smoketest until Step 3 introduces session.py.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
