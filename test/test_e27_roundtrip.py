"""
Offline “stack round-trip” test for E27:

message dict -> presentation.encrypt_schema0_envelope()
             -> (test-local) link-layer frame builder (STARTCHAR/escape/CRC/length)
             -> framing.deframe_feed() (stream parsing)
             -> presentation.decrypt_schema0_envelope()
             -> recovered dict

This test is intentionally deterministic (fixed session key).
It does NOT require network or a panel.
"""

from __future__ import annotations

import json

import pytest


def _e27_frame_build(*, protocol_byte: int, ciphertext: bytes) -> bytes:
    """
    Build an on-wire E27 framed message (STARTCHAR + escaped + CRC).

    The deframer expects:
      - STARTCHAR (0x7E) not included in CRC
      - payload layout: [protocol][length_le16][ciphertext...][crc_le16]
      - length includes protocol+length+ciphertext+crc (i.e. total bytes from protocol through crc)
      - escape rule: any literal 0x7E in the framed payload is encoded as 0x7E 0x00
    """
    from elke27_lib.util import calculate_crc16_checksum

    STARTCHAR = 0x7E

    if not (0 <= protocol_byte <= 0xFF):
        raise ValueError("protocol_byte out of range")

    # total length includes protocol + length(2) + ciphertext + crc(2)
    total_len = 1 + 2 + len(ciphertext) + 2

    unescaped = bytearray()
    unescaped.append(protocol_byte & 0xFF)
    unescaped.extend(int(total_len).to_bytes(2, "little", signed=False))
    unescaped.extend(ciphertext)

    crc = calculate_crc16_checksum(0, unescaped, 0, len(unescaped))
    unescaped.extend(int(crc).to_bytes(2, "little", signed=False))

    # escape + startchar
    out = bytearray([STARTCHAR])
    for b in unescaped:
        if b == STARTCHAR:
            out.append(STARTCHAR)
            out.append(0x00)
        else:
            out.append(b)

    return bytes(out)


def _deframe_one_or_fail(chunks: list[bytes]) -> bytes:
    """
    Feed chunks to deframe_feed until one OK frame arrives.
    Returns frame_no_crc (protocol+len+ciphertext).
    """
    from elke27_lib.framing import DeframeState, deframe_feed

    st = DeframeState()
    ok_frames: list[bytes] = []
    errors = 0

    for chunk in chunks:
        results = deframe_feed(st, chunk)
        for r in results:
            if r.ok and r.frame_no_crc is not None:
                ok_frames.append(r.frame_no_crc)
            elif not r.ok:
                errors += 1

    assert errors == 0, f"unexpected deframe errors: {errors}"
    assert len(ok_frames) == 1, f"expected 1 ok frame, got {len(ok_frames)}"
    return ok_frames[0]


def test_e27_encrypt_frame_deframe_decrypt_roundtrip():
    # Import real modules (not fakes)
    from elke27_lib.message import build_area_get_status
    from elke27_lib.presentation import encrypt_schema0_envelope, decrypt_schema0_envelope

    session_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")  # 16 bytes

    original = build_area_get_status(seq=111, session_id=424242, area_id=1)
    payload = json.dumps(original, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    protocol_byte, ciphertext = encrypt_schema0_envelope(payload=payload, session_key=session_key)

    framed = _e27_frame_build(protocol_byte=protocol_byte, ciphertext=ciphertext)

    # Feed in two chunks to emulate TCP segmentation
    frame_no_crc = _deframe_one_or_fail([framed[:7], framed[7:]])

    got_protocol = frame_no_crc[0]
    got_ciphertext = frame_no_crc[3:]  # strip protocol + length(2)

    env = decrypt_schema0_envelope(
        protocol_byte=got_protocol,
        ciphertext=got_ciphertext,
        session_key=session_key,
    )

    decoded = json.loads(env.payload.decode("utf-8"))
    assert decoded == original


def test_e27_deframer_can_handle_multiple_frames_in_one_chunk():
    from elke27_lib.message import build_authenticate, build_area_get_status
    from elke27_lib.presentation import encrypt_schema0_envelope, decrypt_schema0_envelope
    from elke27_lib.framing import DeframeState, deframe_feed

    session_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")  # 16 bytes

    msg1 = build_authenticate(seq=110, pin=4231)
    msg2 = build_area_get_status(seq=111, session_id=424242, area_id=1)

    p1 = json.dumps(msg1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    p2 = json.dumps(msg2, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    proto1, c1 = encrypt_schema0_envelope(payload=p1, session_key=session_key)
    proto2, c2 = encrypt_schema0_envelope(payload=p2, session_key=session_key)

    f1 = _e27_frame_build(protocol_byte=proto1, ciphertext=c1)
    f2 = _e27_frame_build(protocol_byte=proto2, ciphertext=c2)

    combined = f1 + f2

    st = DeframeState()
    results = deframe_feed(st, combined)

    ok_frames = [r.frame_no_crc for r in results if r.ok and r.frame_no_crc is not None]
    assert len(ok_frames) == 2

    decoded = []
    for frame_no_crc in ok_frames:
        proto = frame_no_crc[0]
        cipher = frame_no_crc[3:]
        env = decrypt_schema0_envelope(protocol_byte=proto, ciphertext=cipher, session_key=session_key)
        decoded.append(json.loads(env.payload.decode("utf-8")))

    assert decoded[0] == msg1
    assert decoded[1] == msg2
