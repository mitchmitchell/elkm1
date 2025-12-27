# test/test_e27_presentation.py

from __future__ import annotations

import os
import pytest

from elke27_lib.presentation import (
    API_LINK_IV,
    E27_MAGIC,
    E27ProtocolError,
    PROTOCOL_ENCRYPTED_FLAG,
    decrypt_api_link_response,
    decrypt_key_field_with_linkkey,
    decrypt_schema0_envelope,
    encrypt_schema0_envelope,
    protocol_is_encrypted,
    protocol_padding_len,
    _aes128_cbc_encrypt,
)
from elke27_lib.util import swap_endianness, calculate_block_padding


def test_e27_presentation():
    """
    End-to-end deterministic presentation-layer validation:

    - schema-0 encrypt -> decrypt roundtrip
    - protocol byte encrypted flag + pad_len nibble
    - MAGIC validation and envelope field parsing
    """
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    payload = b'{"op":"area.get_status","area":1}'

    src = 1
    dest = 2
    head = 0
    envelope_seq = 123456

    protocol_byte, ciphertext = encrypt_schema0_envelope(
        src=src,
        dest=dest,
        head=head,
        payload=payload,
        session_key=session_key,
        envelope_seq=envelope_seq,
        iv=API_LINK_IV,
    )

    assert protocol_is_encrypted(protocol_byte) is True
    assert len(ciphertext) % 16 == 0
    assert len(ciphertext) > 0

    # Pad length is encoded in the low nibble of protocol byte.
    base_len = 4 + 1 + 1 + 1 + len(payload) + 2  # seq+src+dest+head+payload+MAGIC
    expected_pad = calculate_block_padding(base_len)
    assert protocol_padding_len(protocol_byte) == expected_pad

    env = decrypt_schema0_envelope(
        protocol_byte=protocol_byte,
        ciphertext=ciphertext,
        session_key=session_key,
        iv=API_LINK_IV,
        require_magic=True,
    )

    assert env.envelope_seq == envelope_seq
    assert env.src == src
    assert env.dest == dest
    assert env.head == head
    assert env.payload == payload
    assert env.padding_len == expected_pad
    assert env.magic == E27_MAGIC


def test_e27_presentation_rejects_non_encrypted_protocol_byte():
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    bogus_protocol_byte = 0x00  # not encrypted
    ciphertext = b"\x00" * 16

    with pytest.raises(E27ProtocolError) as ei:
        decrypt_schema0_envelope(
            protocol_byte=bogus_protocol_byte,
            ciphertext=ciphertext,
            session_key=session_key,
            iv=API_LINK_IV,
            require_magic=True,
        )

    assert "non-encrypted" in str(ei.value).lower()


def test_e27_presentation_magic_mismatch_raises():
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    payload = b'{"op":"control.get_version_info"}'

    protocol_byte, ciphertext = encrypt_schema0_envelope(
        src=1,
        dest=2,
        head=0,
        payload=payload,
        session_key=session_key,
        envelope_seq=1,
        iv=API_LINK_IV,
    )

    # Corrupt ciphertext so decrypt succeeds structurally but MAGIC is likely wrong.
    # We flip a byte near the end; length remains a multiple of 16.
    corrupted = bytearray(ciphertext)
    corrupted[-1] ^= 0x01

    with pytest.raises(E27ProtocolError) as ei:
        decrypt_schema0_envelope(
            protocol_byte=protocol_byte,
            ciphertext=bytes(corrupted),
            session_key=session_key,
            iv=API_LINK_IV,
            require_magic=True,
        )

    assert "magic mismatch" in str(ei.value).lower()


def test_e27_presentation_decrypt_api_link_response_roundtrip_minimal():
    """
    api_link response decrypt path:
      ciphertext -> swap -> AES_DEC -> swap -> seq+src+dest+json+MAGIC+padding
    """
    key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    seq = 123
    src = 1
    dest = 0
    json_bytes = b'{"ok":true}'

    base_len = 4 + 1 + 1 + 1 + len(json_bytes) + 2
    pad_len = calculate_block_padding(base_len)
    protocol_byte = PROTOCOL_ENCRYPTED_FLAG | (pad_len & 0x0F)

    pt_full = bytearray()
    pt_full.extend(seq.to_bytes(4, "little"))
    pt_full.append(src)
    pt_full.append(dest)
    pt_full.append(0x00)
    pt_full.extend(json_bytes)
    pt_full.extend(E27_MAGIC.to_bytes(2, "little"))
    pt_full.extend(b"\x00" * pad_len)
    assert len(pt_full) % 16 == 0

    # Encrypt inverse of decrypt_api_link_response:
    # decrypt does: pt = swap(AES_DEC(key, swap(ct)))
    # so encrypt does: ct = swap(AES_ENC(key, swap(pt)))
    key_swapped = swap_endianness(key)
    pt_swapped = swap_endianness(bytes(pt_full))
    ct_swapped = _aes128_cbc_encrypt(key=key_swapped, iv=API_LINK_IV, plaintext=pt_swapped)
    ciphertext = swap_endianness(ct_swapped)

    out_ack, out_json = decrypt_api_link_response(
        protocol_byte=protocol_byte,
        ciphertext=ciphertext,
        tempkey_hex=key.hex(),
        iv=API_LINK_IV,
    )
    assert out_ack == 0
    assert out_json == json_bytes


def test_e27_presentation_decrypt_key_field_with_linkkey_roundtrip():
    """
    hello key-field decrypt helper:
      key = swap(linkkey)
      ct_swapped = swap(ciphertext)
      pt = AES_DEC(key, ct_swapped)
      (no final swap on pt in this helper)
    """
    linkkey = bytes.fromhex("00112233445566778899aabbccddeeff")
    pt = os.urandom(16)

    key_swapped = swap_endianness(linkkey)
    ct_swapped = _aes128_cbc_encrypt(key=key_swapped, iv=API_LINK_IV, plaintext=pt)
    ciphertext = swap_endianness(ct_swapped)

    out = decrypt_key_field_with_linkkey(
        linkkey_hex=linkkey.hex(),
        ciphertext_hex=ciphertext.hex(),
        iv=API_LINK_IV,
    )
    assert out == pt
