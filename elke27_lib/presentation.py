"""
elkm1.elke27_lib.presentation

E27 presentation-layer pack/unpack helpers derived 1:1 from the Node-RED prototype.

Inbound (schema-0 encrypted container):
- Input: frame_no_crc bytes from link layer:
    [0]=protocol, [1..2]=length (LE), [3..]=dataFrame (ciphertext or clear)
  (CRC already stripped by deframer; STARTCHAR omitted.)
- protocol:
    - encrypted flag: bit7 (0x80)
    - padding length: low nibble (0x0F)
- If encrypted:
    - Select key:
        - if session_key_hex provided: key = bytes.fromhex(session_key_hex)  (NO swap)
        - else: key = swap(bytes.fromhex(tempkey_hex))  (tempkey path)
    - plaintext = swap( AES_CBC_Decrypt(key, IV, swap(ciphertext)) )
    - parse:
        seq (u32 LE) at 0
        src at 4
        dest at 5
        head at 6? (Node-RED IN path ignores head and treats JSON at offset 6)
    - magic is u16 LE located at: len(plaintext) - (paddinglen + 2)
    - JSON bytes are: plaintext[6 : len - (paddinglen + 2)]
- If not encrypted:
    - (Not needed for smoketest; return empty payload for now)

Outbound (schema-0 encrypted container):
- Input: json_bytes to send (UTF-8 bytes)
- Plaintext envelope built as in Node-RED Presentation Layer - OUT:
    seq u32 LE (default 1234)
    src u8 (default 1)
    dest u8 (default 0)
    head u8 (default 0)
    json bytes
    magic u16 LE (0x422A)
    padding bytes (0x00) to 16-byte boundary
- paddingBytes computed with:
    (16 - (length % 16)) & 15
  where base length is: 4 + 2 + 1 + len(json) + 2
- protocol byte = 0x80 | paddingBytes
- ciphertext = swap( AES_CBC_Encrypt(sessionKey, IV, swap(plaintext)) )
- Return (protocol_byte, ciphertext) to be framed by link-layer.

Notes:
- IV is constant API_LINK_IV = bytes(range(16))
- MAGIC is 0x422A (StaticData.MAGIC)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Tuple

from .encryption import (
    API_LINK_IV,
    E27CryptoError,
    calculate_block_padding,
    decrypt_schema0_ciphertext,
    encrypt_schema0_plaintext,
    sessionkey_hex_to_aes_key,
    tempkey_hex_to_aes_key,
)


MAGIC: int = 0x422A


class E27PresentationError(ValueError):
    """Raised when presentation-layer parsing/validation fails."""


@dataclass(frozen=True)
class PresentationMeta:
    protocol: int
    encrypted: bool
    padding_len: int
    seq: Optional[int] = None
    src: Optional[int] = None
    dest: Optional[int] = None
    head: Optional[int] = None
    length_field: Optional[int] = None


def _u16_le(b0: int, b1: int) -> int:
    return (b0 & 0xFF) | ((b1 & 0xFF) << 8)


def unpack_inbound(
    *,
    frame_no_crc: bytes,
    tempkey_hex: Optional[str],
    session_key_hex: Optional[str],
) -> Tuple[PresentationMeta, bytes]:
    """
    Unpack an inbound link-layer frame (CRC stripped) into JSON bytes.

    Args:
        frame_no_crc: bytes including protocol + length(LE) + dataFrame (ciphertext or clear)
        tempkey_hex: used when session_key_hex is None (api_link response decrypt)
        session_key_hex: used for normal schema-0 decrypt

    Returns:
        (meta, json_bytes)

    Raises:
        E27PresentationError on parse errors, invalid lengths, magic mismatch, etc.
    """
    if frame_no_crc is None:
        raise E27PresentationError("unpack_inbound: frame_no_crc is None")
    if len(frame_no_crc) < 3:
        raise E27PresentationError(f"unpack_inbound: frame too short ({len(frame_no_crc)} bytes)")

    protocol = frame_no_crc[0] & 0xFF
    length_field = _u16_le(frame_no_crc[1], frame_no_crc[2])
    encrypted = (protocol & 0x80) == 0x80
    padding_len = protocol & 0x0F

    meta = PresentationMeta(
        protocol=protocol,
        encrypted=encrypted,
        padding_len=padding_len,
        length_field=length_field,
    )

    # Link-layer length includes CRC, but CRC has been stripped already in frame_no_crc.
    # Node-RED "IN" uses:
    #   msglength = readInt16LE(1) - 2   # account for stripped CRC
    #   dataFrameLen = msglength - 3     # strip protocol+length
    # That implies ciphertext bytes count should be: (length_field - 2) - 3 = length_field - 5
    # However, on TCP we should trust the actual bytes received rather than recompute.
    if len(frame_no_crc) < 3:
        return meta, b""

    data_frame = frame_no_crc[3:]

    if not encrypted:
        # For now, return the raw data_frame; callers may parse JSON directly.
        # (Hello response appears clear JSON at the TCP layer, not schema-0 encrypted.)
        return meta, bytes(data_frame)

    # Encrypted schema-0 decrypt
    if session_key_hex:
        key = sessionkey_hex_to_aes_key(session_key_hex)
    else:
        if not tempkey_hex:
            raise E27PresentationError("unpack_inbound: tempkey_hex required when session_key_hex is not provided")
        key = tempkey_hex_to_aes_key(tempkey_hex)

    try:
        plaintext = decrypt_schema0_ciphertext(key=key, ciphertext=bytes(data_frame), iv=API_LINK_IV)
    except E27CryptoError as e:
        raise E27PresentationError(f"unpack_inbound: decrypt failed: {e}") from e

    if len(plaintext) < 8:
        raise E27PresentationError(f"unpack_inbound: decrypted plaintext too short ({len(plaintext)} bytes)")

    # Extract envelope fields
    seq = int.from_bytes(plaintext[0:4], "little", signed=False)
    src = plaintext[4] & 0xFF
    dest = plaintext[5] & 0xFF
    head = plaintext[6] & 0xFF  # present in outbound builder; inbound Node-RED ignores but we record it

    # MAGIC check at end - (padding + 2)
    if padding_len < 0 or padding_len > 15:
        raise E27PresentationError(f"unpack_inbound: invalid padding_len {padding_len}")

    magic_off = len(plaintext) - (padding_len + 2)
    if magic_off < 0 or magic_off + 2 > len(plaintext):
        raise E27PresentationError("unpack_inbound: invalid magic offset derived from padding")

    magic = int.from_bytes(plaintext[magic_off : magic_off + 2], "little", signed=False)
    if magic != MAGIC:
        raise E27PresentationError(f"unpack_inbound: MAGIC mismatch (got 0x{magic:04X}, expected 0x{MAGIC:04X})")

    json_start = 6  # Node-RED IN slices from 6, not 7; it does NOT include 'head' in message bytes
    json_end = magic_off
    if json_end < json_start:
        raise E27PresentationError("unpack_inbound: invalid JSON slice (end before start)")

    json_bytes = plaintext[json_start:json_end]

    meta = PresentationMeta(
        protocol=protocol,
        encrypted=encrypted,
        padding_len=padding_len,
        seq=seq,
        src=src,
        dest=dest,
        head=head,
        length_field=length_field,
    )

    return meta, bytes(json_bytes)


def pack_outbound_schema0(
    *,
    json_bytes: bytes,
    session_key_hex: str,
    src: int = 1,
    dest: int = 0,
    seq: int = 1234,
    head: int = 0,
) -> Tuple[int, bytes]:
    """
    Build a schema-0 encrypted presentation-layer dataFrame and protocol byte, matching Node-RED.

    Returns:
        (protocol_byte, ciphertext_data_frame)

    Caller must feed these into link-layer framing.frame_build(protocol_byte, data_frame).

    Raises:
        E27PresentationError on invalid inputs.
    """
    if json_bytes is None:
        raise E27PresentationError("pack_outbound_schema0: json_bytes is None")
    if not isinstance(json_bytes, (bytes, bytearray)):
        raise E27PresentationError(f"pack_outbound_schema0: json_bytes must be bytes-like, got {type(json_bytes).__name__}")
    if not session_key_hex:
        raise E27PresentationError("pack_outbound_schema0: session_key_hex is required")
    if not (0 <= src <= 0xFF and 0 <= dest <= 0xFF and 0 <= head <= 0xFF):
        raise E27PresentationError("pack_outbound_schema0: src/dest/head must be 0..255")
    if not (0 <= seq <= 0xFFFFFFFF):
        raise E27PresentationError("pack_outbound_schema0: seq must fit uint32")

    payload = bytes(json_bytes)

    # Base length: seq(4) + src/dest(2) + head(1) + payload + magic(2)
    base_len = 4 + 2 + 1 + len(payload) + 2
    padding = calculate_block_padding(base_len)
    total_len = base_len + padding

    protocol_byte = 0x80 | (padding & 0x0F)

    # Build plaintext envelope
    buf = bytearray(total_len)
    idx = 0

    buf[idx : idx + 4] = int(seq).to_bytes(4, "little", signed=False)
    idx += 4

    buf[idx] = src & 0xFF
    idx += 1
    buf[idx] = dest & 0xFF
    idx += 1
    buf[idx] = head & 0xFF
    idx += 1

    buf[idx : idx + len(payload)] = payload
    idx += len(payload)

    # MAGIC then padding (Node-RED writes MAGIC first, then fills padding after it)
    buf[idx : idx + 2] = int(MAGIC).to_bytes(2, "little", signed=False)
    idx += 2

    if padding:
        # Padding bytes are 0x00
        buf[idx : idx + padding] = b"\x00" * padding
        idx += padding

    if idx != total_len:
        raise E27PresentationError(
            f"pack_outbound_schema0: internal length mismatch (wrote {idx}, expected {total_len})"
        )

    # Encrypt schema-0 with session key (NO key swap)
    key = sessionkey_hex_to_aes_key(session_key_hex)
    try:
        ciphertext = encrypt_schema0_plaintext(key=key, plaintext=bytes(buf), iv=API_LINK_IV)
    except E27CryptoError as e:
        raise E27PresentationError(f"pack_outbound_schema0: encrypt failed: {e}") from e

    return protocol_byte, ciphertext
