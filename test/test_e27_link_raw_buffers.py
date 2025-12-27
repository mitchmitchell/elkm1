from __future__ import annotations

import json
import os
import socket
import time

import pytest

from elke27_lib.framing import DeframeState, deframe_feed
from elke27_lib.linking import (
    E27Identity,
    build_api_link_request,
    derive_pass_tempkey_with_cnonce,
    send_unframed_json,
    wait_for_discovery_nonce,
)
from elke27_lib.presentation import decrypt_api_link_response


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    if value == "":
        return default
    return value


def _require_env(name: str) -> str:
    value = _env(name)
    if not value:
        pytest.skip(f"Missing {name} for live link test.")
    return value


@pytest.mark.integration
def test_link_raw_framed_and_deframed_buffers() -> None:
    host = _require_env("ELKE27_HOST")
    port = int(_env("ELKE27_PORT", "2101") or 2101)
    access_code = _require_env("ELKE27_ACCESS_CODE")
    passphrase = _require_env("ELKE27_PASSPHRASE")
    mn = _require_env("ELKE27_MN")
    sn = _require_env("ELKE27_SN")
    fwver = _require_env("ELKE27_FWVER")
    hwver = _require_env("ELKE27_HWVER")
    osver = _require_env("ELKE27_OSVER")

    timeout_s = float(_env("ELKE27_TIMEOUT_S", "5.0") or 5.0)

    identity = E27Identity(mn=mn, sn=sn, fwver=fwver, hwver=hwver, osver=osver)

    with socket.create_connection((host, port), timeout=timeout_s) as sock:
        nonce = wait_for_discovery_nonce(sock, timeout_s=timeout_s)
        cnonce = os.urandom(20).hex().lower()
        pass8, tempkey_hex = derive_pass_tempkey_with_cnonce(
            access_code=access_code,
            passphrase=passphrase,
            nonce=nonce,
            cnonce=cnonce,
            mn=mn,
            sn=sn,
        )

        req = build_api_link_request(seq=110, identity=identity, pass_hex8=pass8, cnonce_hex=cnonce)
        send_unframed_json(sock, req)

        state = DeframeState()
        raw_chunks: list[bytes] = []
        frame_no_crc: bytes | None = None

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and frame_no_crc is None:
            remaining = max(0.0, deadline - time.monotonic())
            sock.settimeout(min(0.5, remaining))
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            raw_chunks.append(chunk)

            for res in deframe_feed(state, chunk):
                if res.ok and res.frame_no_crc:
                    frame_no_crc = res.frame_no_crc
                    break

        if frame_no_crc is None:
            pytest.fail("No framed response received within timeout.")

        framed_hex = b"".join(raw_chunks).hex()
        deframed_hex = frame_no_crc.hex()
        encrypted_hex = frame_no_crc[3:].hex()
        _ack, decrypted_bytes = decrypt_api_link_response(
            protocol_byte=frame_no_crc[0],
            ciphertext=frame_no_crc[3:],
            tempkey_hex=tempkey_hex,
        )
        decrypted_hex = decrypted_bytes.hex()
        try:
            decrypted_text = decrypted_bytes.decode("utf-8", errors="strict")
            decrypted_json = json.loads(decrypted_text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            decrypted_json = None

        print(f"\nframed_hex={framed_hex}")
        print(f"deframed_hex={deframed_hex}")
        print(f"encrypted_hex={encrypted_hex}")
        print(f"decrypted_hex={decrypted_hex}")
        if decrypted_json is not None:
            print(f"decrypted_json={decrypted_json}")
