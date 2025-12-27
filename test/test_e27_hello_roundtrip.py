from __future__ import annotations

import json
import os
import socket
import threading

from elke27_lib.hello import E27Identity, perform_hello
from elke27_lib.presentation import API_LINK_IV, _aes128_cbc_encrypt
from elke27_lib.util import swap_endianness


def _encrypt_key_field(*, linkkey_hex: str, plaintext: bytes) -> str:
    key = bytes.fromhex(linkkey_hex)
    key_swapped = swap_endianness(key)
    ct_swapped = _aes128_cbc_encrypt(key=key_swapped, iv=API_LINK_IV, plaintext=plaintext)
    ciphertext = swap_endianness(ct_swapped)
    return ciphertext.hex()


def test_hello_roundtrip_socketpair() -> None:
    identity = E27Identity(mn="0222", sn="001122334455", fwver="1.0", hwver="1.0", osver="1.0")
    linkkey_hex = "00112233445566778899aabbccddeeff"
    session_id = 12345
    session_key = os.urandom(16)
    hmac_key = os.urandom(32)

    sk_hex = _encrypt_key_field(linkkey_hex=linkkey_hex, plaintext=session_key)
    shm_hex = _encrypt_key_field(linkkey_hex=linkkey_hex, plaintext=hmac_key)

    hello_response = json.dumps(
        {
            "hello": {
                "session_id": session_id,
                "sk": sk_hex,
                "shm": shm_hex,
                "error_code": 0,
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")

    client, server = socket.socketpair()

    def _server() -> None:
        try:
            server.recv(4096)
            server.sendall(hello_response)
        finally:
            server.close()

    thread = threading.Thread(target=_server, daemon=True)
    thread.start()

    try:
        keys = perform_hello(sock=client, identity=identity, linkkey_hex=linkkey_hex, seq=110, timeout_s=2.0)
    finally:
        client.close()
        thread.join(timeout=1.0)

    assert keys.session_id == session_id
    assert bytes.fromhex(keys.session_key_hex) == session_key
    assert bytes.fromhex(keys.hmac_key_hex) == hmac_key
