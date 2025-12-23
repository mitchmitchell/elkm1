"""
E27 Presentation Layer (E27 schema-0 encryption/decryption, padding, MAGIC handling).

This module is intentionally HA-agnostic and contains only protocol/presentation logic.

Key behaviors proven via live panel + Node-RED prototype:
- AES-128-CBC with fixed IV (API_LINK_IV / initVectorBytes)
- 32-bit word endianness swap is applied *around* AES operations
- For schema-0 encrypted payloads, plaintext ends with MAGIC and optional zero padding
- Some decrypted payloads begin with an ack/head byte before JSON (DDR-0017)
- The api_link response decrypt path yields: ack byte + JSON (no envelope fields observed)

Crypto backend: `cryptography` (preferred for production).

Related DDRs:
- DDR-0017: Ack/Head Byte Before JSON
- DDR-0019: Provisioning vs Runtime Responsibilities and Module Boundaries
- DDR-0020: api_link failure is silent (timeout) — handled by caller (linking/session)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import E27ErrorContext, E27ProtocolError
from .util import swap_endianness, calculate_block_padding  # swap_endianness is the 32-bit word swap


# Fixed IV used by E27 for AES-128-CBC in observed flows
API_LINK_IV: Final[bytes] = bytes(range(16))  # 00 01 02 ... 0f (Java initVectorBytes)

# Observed MAGIC constant (from Node-RED StaticData.MAGIC)
E27_MAGIC: Final[int] = 0x422A

# Protocol bits (observed in Node-RED)
PROTOCOL_ENCRYPTED_FLAG: Final[int] = 0x80
PROTOCOL_PADDING_MASK: Final[int] = 0x0F  # low nibble carries padding length in schema-0 encrypted


@dataclass(frozen=True, slots=True)
class E27DecryptedEnvelope:
    """
    Decrypted schema-0 envelope.

    Note: You previously concluded envelope 'seq' does not need to be tracked now,
    but we still parse it for completeness/validation.
    """
    envelope_seq: int
    src: int
    dest: int
    head: int
    payload: bytes  # JSON bytes (or other protocol data), not decoded here
    padding_len: int
    magic: int


def _require_len(name: str, data: bytes, multiple: int) -> None:
    if len(data) == 0 or (len(data) % multiple) != 0:
        raise E27ProtocolError(
            f"{name} length must be a non-zero multiple of {multiple}, got {len(data)}.",
            context=E27ErrorContext(phase="presentation_validate", detail=f"{name}_len={len(data)}"),
        )


def _require_key_16(key: bytes, *, context_phase: str) -> None:
    if len(key) != 16:
        raise E27ProtocolError(
            f"AES-128 key must be 16 bytes, got {len(key)}.",
            context=E27ErrorContext(phase=context_phase, detail=f"key_len={len(key)}"),
        )


def _aes128_cbc_decrypt(*, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    _require_key_16(key, context_phase="presentation_decrypt")
    _require_len("ciphertext", ciphertext, 16)
    if len(iv) != 16:
        raise E27ProtocolError(
            f"IV must be 16 bytes, got {len(iv)}.",
            context=E27ErrorContext(phase="presentation_decrypt", detail=f"iv_len={len(iv)}"),
        )

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _aes128_cbc_encrypt(*, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    _require_key_16(key, context_phase="presentation_encrypt")
    _require_len("plaintext", plaintext, 16)
    if len(iv) != 16:
        raise E27ProtocolError(
            f"IV must be 16 bytes, got {len(iv)}.",
            context=E27ErrorContext(phase="presentation_encrypt", detail=f"iv_len={len(iv)}"),
        )

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def protocol_padding_len(protocol_byte: int) -> int:
    """Extract padding length from protocol byte (low nibble)."""
    return int(protocol_byte & PROTOCOL_PADDING_MASK)


def protocol_is_encrypted(protocol_byte: int) -> bool:
    return (protocol_byte & PROTOCOL_ENCRYPTED_FLAG) == PROTOCOL_ENCRYPTED_FLAG


def decrypt_schema0_envelope(
    *,
    protocol_byte: int,
    ciphertext: bytes,
    session_key: bytes,
    iv: bytes = API_LINK_IV,
    require_magic: bool = True,
) -> E27DecryptedEnvelope:
    """
    Decrypt a schema-0 encrypted message and parse the envelope:
      seq(4 LE) + src(1) + dest(1) + head(1) + payload + MAGIC(2 LE) + padding(0..15)

    The AES decrypt is wrapped with swap_endianness() on 32-bit word boundaries, matching
    the working Node-RED prototype and live tests:
      plaintext = swap( AES_DEC( swap(ciphertext) ) ); then swap(plaintext)

    `padding_len` is derived from protocol byte low nibble.

    Raises E27ProtocolError on invalid lengths, MAGIC mismatch, or structural errors.
    """
    if not protocol_is_encrypted(protocol_byte):
        raise E27ProtocolError(
            "decrypt_schema0_envelope called for non-encrypted protocol byte.",
            context=E27ErrorContext(phase="presentation_decrypt", detail=f"protocol=0x{protocol_byte:02x}"),
        )

    pad_len = protocol_padding_len(protocol_byte)

    # Ciphertext is 32-bit word swapped before AES, per prototype
    ct_swapped = swap_endianness(ciphertext)
    pt = _aes128_cbc_decrypt(key=session_key, iv=iv, ciphertext=ct_swapped)
    pt = swap_endianness(pt)

    if len(pt) < (4 + 1 + 1 + 1 + 2):
        raise E27ProtocolError(
            f"Decrypted plaintext too short for envelope: {len(pt)} bytes.",
            context=E27ErrorContext(phase="presentation_decrypt", detail=f"pt_len={len(pt)}"),
        )

    # Parse fixed envelope header
    envelope_seq = int.from_bytes(pt[0:4], "little", signed=False)
    src = pt[4]
    dest = pt[5]
    head = pt[6]

    # MAGIC sits just before padding bytes at end: [... payload ...][MAGIC(2)][PAD...]
    if pad_len < 0 or pad_len > 15:
        raise E27ProtocolError(
            f"Invalid padding length in protocol byte: {pad_len}.",
            context=E27ErrorContext(phase="presentation_decrypt", detail=f"pad_len={pad_len}"),
        )

    magic_off = len(pt) - (pad_len + 2)
    if magic_off < 7:
        raise E27ProtocolError(
            "Decrypted plaintext too short for MAGIC/padding layout.",
            context=E27ErrorContext(phase="presentation_decrypt", detail=f"magic_off={magic_off}"),
        )

    magic = int.from_bytes(pt[magic_off : magic_off + 2], "little", signed=False)
    if require_magic and magic != E27_MAGIC:
        raise E27ProtocolError(
            f"MAGIC mismatch after decrypt (got 0x{magic:04x}, expected 0x{E27_MAGIC:04x}).",
            context=E27ErrorContext(phase="presentation_decrypt", detail=f"magic=0x{magic:04x}"),
        )

    payload = pt[7:magic_off]  # payload bytes between head and MAGIC

    return E27DecryptedEnvelope(
        envelope_seq=envelope_seq,
        src=src,
        dest=dest,
        head=head,
        payload=payload,
        padding_len=pad_len,
        magic=magic,
    )


def encrypt_schema0_envelope(
    *,
    payload: bytes,
    session_key: bytes,
    src: int = 1,
    dest: int = 0,
    head: int = 0,
    envelope_seq: int = 0,
    iv: bytes = API_LINK_IV,
) -> Tuple[int, bytes]:
    """
    Build and encrypt a schema-0 envelope.

    Layout before AES:
      seq(4 LE) + src(1) + dest(1) + head(1) + payload + MAGIC(2 LE) + padding(0..15 of 0x00)

    Padding is computed to make total length a multiple of 16, and padding length
    is encoded into protocol byte low nibble, with encrypted flag set.

    Returns (protocol_byte, ciphertext_bytes)
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise E27ProtocolError(
            "payload must be bytes.",
            context=E27ErrorContext(phase="presentation_encrypt"),
        )
    if not (0 <= src <= 255 and 0 <= dest <= 255 and 0 <= head <= 255):
        raise E27ProtocolError(
            "src/dest/head must be 0..255.",
            context=E27ErrorContext(phase="presentation_encrypt", detail=f"src={src},dest={dest},head={head}"),
        )
    if envelope_seq < 0 or envelope_seq > 0xFFFFFFFF:
        raise E27ProtocolError(
            "envelope_seq must be a 32-bit unsigned integer.",
            context=E27ErrorContext(phase="presentation_encrypt", detail=f"seq={envelope_seq}"),
        )

    base_len = 4 + 1 + 1 + 1 + len(payload) + 2
    pad_len = calculate_block_padding(base_len)
    if pad_len < 0 or pad_len > 15:
        raise E27ProtocolError(
            f"Calculated invalid padding length: {pad_len}.",
            context=E27ErrorContext(phase="presentation_encrypt", detail=f"base_len={base_len}"),
        )

    total_len = base_len + pad_len
    if total_len % 16 != 0:
        raise E27ProtocolError(
            "Envelope length is not a multiple of 16 after padding (internal error).",
            context=E27ErrorContext(phase="presentation_encrypt", detail=f"total_len={total_len}"),
        )

    buf = bytearray(total_len)
    buf[0:4] = int(envelope_seq).to_bytes(4, "little", signed=False)
    buf[4] = src & 0xFF
    buf[5] = dest & 0xFF
    buf[6] = head & 0xFF

    # payload
    p_off = 7
    buf[p_off : p_off + len(payload)] = payload

    # MAGIC
    m_off = p_off + len(payload)
    buf[m_off : m_off + 2] = int(E27_MAGIC).to_bytes(2, "little", signed=False)

    # padding zeros already present by default in bytearray()

    protocol = PROTOCOL_ENCRYPTED_FLAG | (pad_len & PROTOCOL_PADDING_MASK)

    # Apply 32-bit swap around AES, matching working prototype
    pt_swapped = swap_endianness(bytes(buf))
    ct = _aes128_cbc_encrypt(key=session_key, iv=iv, plaintext=pt_swapped)
    ct = swap_endianness(ct)

    return protocol, ct


def decrypt_api_link_response(
    *,
    ciphertext: bytes,
    tempkey_hex: str,
    iv: bytes = API_LINK_IV,
) -> Tuple[int, bytes]:
    """
    Decrypt the api_link response payload.

    Observed plaintext format (from your live log):
      [ack_byte][JSON bytes...]

    Unlike general schema-0 envelopes, the api_link response was handled in Node-RED
    by stripping a leading ack byte and parsing the remaining bytes as JSON without
    MAGIC/padding parsing.

    Returns: (ack_byte, json_bytes)

    NOTE: This does NOT validate MAGIC or parse envelope fields.
    """
    try:
        key = bytes.fromhex(tempkey_hex)
    except ValueError as e:
        raise E27ProtocolError(
            "tempkey_hex is not valid hex.",
            context=E27ErrorContext(phase="api_link_decrypt"),
            cause=e,
        )
    _require_key_16(key, context_phase="api_link_decrypt")

    ct_swapped = swap_endianness(ciphertext)
    pt = _aes128_cbc_decrypt(key=key, iv=iv, ciphertext=ct_swapped)
    pt = swap_endianness(pt)

    if len(pt) < 2:
        raise E27ProtocolError(
            "api_link decrypt returned too few bytes.",
            context=E27ErrorContext(phase="api_link_decrypt", detail=f"pt_len={len(pt)}"),
        )

    ack = pt[0]
    json_bytes = pt[1:]
    return ack, json_bytes


def decrypt_key_field_with_linkkey(
    *,
    linkkey_hex: str,
    ciphertext_hex: str,
    iv: bytes = API_LINK_IV,
    swap_key_32bit: bool = True,
) -> bytes:
    """
    Helper for hello response fields sk/shm.

    Node-RED proven flow:
      key_bytes = swap_endianness(hex_to_bytes(linkkey))
      plaintext = swap_endianness( AES_DEC( swap_endianness(ciphertext) ) )

    Returns raw decrypted bytes (caller can hex-encode if desired).

    This is provided here so hello.py can stay thin and consistent.
    """
    try:
        key = bytes.fromhex(linkkey_hex)
        ct = bytes.fromhex(ciphertext_hex)
    except ValueError as e:
        raise E27ProtocolError(
            "Invalid hex input to decrypt_key_field_with_linkkey.",
            context=E27ErrorContext(phase="hello_key_decrypt"),
            cause=e,
        )
    _require_key_16(key, context_phase="hello_key_decrypt")
    _require_len("hello_key_ciphertext", ct, 16)

    if swap_key_32bit:
        key = swap_endianness(key)

    ct_swapped = swap_endianness(ct)
    pt = _aes128_cbc_decrypt(key=key, iv=iv, ciphertext=ct_swapped)
    pt = swap_endianness(pt)
    return pt
