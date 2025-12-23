# elkm1/test/e27_test_framing.py
#
# Minimal but high-value tests for E27 link-layer framing/deframing.
#
# These tests assume elke27_lib.framing exports:
#   - DeframeState
#   - deframe_feed(state, chunk) -> list[DeframeResult]
#   - frame_build(protocol_byte: int, data_frame: bytes) -> bytes
#
# And that DeframeResult has:
#   - ok: bool
#   - frame_no_crc: bytes | None
#
# NOTE: These tests do NOT cover api_link/hello (which are unframed). These tests
# validate the link-layer framing used for schema-0 encrypted traffic.

from __future__ import annotations

import pytest

from elke27_lib.framing import DeframeState, deframe_feed, frame_build

STARTCHAR = 0x7E


def _collect_ok_frames(results):
    return [r.frame_no_crc for r in results if getattr(r, "ok", False) and getattr(r, "frame_no_crc", None)]


def test_frame_round_trip_single_chunk():
    state = DeframeState()
    protocol = 0x80
    data_frame = b"\x01\x02\x03\x04\x05\x06\x07\x08"

    framed = frame_build(protocol_byte=protocol, data_frame=data_frame)

    results = deframe_feed(state, framed)
    frames = _collect_ok_frames(results)

    assert len(frames) == 1
    frame_no_crc = frames[0]

    # frame_no_crc keeps protocol + length + data (CRC removed)
    assert frame_no_crc[0] == protocol
    assert frame_no_crc[3:] == data_frame


def test_frame_split_across_chunks():
    state = DeframeState()
    protocol = 0x80
    data_frame = b"0123456789ABCDEF"

    framed = frame_build(protocol_byte=protocol, data_frame=data_frame)

    # Split mid-stream (arbitrary)
    a = framed[:7]
    b = framed[7:]

    r1 = deframe_feed(state, a)
    assert _collect_ok_frames(r1) == []

    r2 = deframe_feed(state, b)
    frames = _collect_ok_frames(r2)

    assert len(frames) == 1
    frame_no_crc = frames[0]
    assert frame_no_crc[0] == protocol
    assert frame_no_crc[3:] == data_frame


def test_multiple_frames_in_one_chunk():
    state = DeframeState()

    framed1 = frame_build(protocol_byte=0x80, data_frame=b"AAA")
    framed2 = frame_build(protocol_byte=0x81, data_frame=b"BBBBBBBB")
    framed3 = frame_build(protocol_byte=0x82, data_frame=b"")

    combined = framed1 + framed2 + framed3
    results = deframe_feed(state, combined)
    frames = _collect_ok_frames(results)

    assert len(frames) == 3
    assert frames[0][0] == 0x80 and frames[0][3:] == b"AAA"
    assert frames[1][0] == 0x81 and frames[1][3:] == b"BBBBBBBB"
    assert frames[2][0] == 0x82 and frames[2][3:] == b""


def test_escape_sequence_round_trip_contains_startchar_in_payload():
    """
    If the payload contains 0x7E, the framer must escape it as 0x7E 0x00.
    The deframer must restore it.
    """
    state = DeframeState()
    protocol = 0x80

    # Put STARTCHAR in the data_frame so it must be escaped
    data_frame = bytes([0x11, 0x22, STARTCHAR, 0x33, 0x44])

    framed = frame_build(protocol_byte=protocol, data_frame=data_frame)

    # Ensure the wire representation includes an escape sequence (heuristic)
    assert bytes([STARTCHAR, 0x00]) in framed

    results = deframe_feed(state, framed)
    frames = _collect_ok_frames(results)

    assert len(frames) == 1
    frame_no_crc = frames[0]
    assert frame_no_crc[0] == protocol
    assert frame_no_crc[3:] == data_frame


def test_resync_on_startchar_followed_by_nonzero_starts_new_frame():
    """
    Node-RED rule:
      STARTCHAR followed by non-zero is ALWAYS a new message, and that byte is the protocol byte.
    This test injects garbage, then STARTCHAR + protocol byte for a new valid frame.
    """
    state = DeframeState()

    good = frame_build(protocol_byte=0x80, data_frame=b"OK")
    assert good[0] == STARTCHAR

    # Create a stream where we start a frame, then inject a resync trigger mid-way:
    #   STARTCHAR, then a partial header, then another STARTCHAR and a non-zero protocol byte.
    # We simulate this by chopping a valid frame early and gluing a new valid frame.
    partial = good[:4]  # START + protocol + 2 bytes of length maybe incomplete
    # Now inject a resync trigger. We want STARTCHAR followed by non-zero protocol (0x81).
    # Then append a complete valid frame with protocol 0x81.
    new_good = frame_build(protocol_byte=0x81, data_frame=b"NEW")

    stream = partial + bytes([STARTCHAR, 0x81]) + new_good[1:]  # omit STARTCHAR from new_good (already injected)
    results = deframe_feed(state, stream)
    frames = _collect_ok_frames(results)

    # We should get at least the second frame; depending on implementation we may or may not get the first.
    assert any(f[0] == 0x81 and f[3:] == b"NEW" for f in frames)


def test_bad_crc_does_not_prevent_parsing_following_frame():
    """
    If a frame has a bad CRC, deframer should report an error but continue scanning for the next frame.
    """
    state = DeframeState()

    good1 = frame_build(protocol_byte=0x80, data_frame=b"FIRST")
    good2 = frame_build(protocol_byte=0x81, data_frame=b"SECOND")

    # Corrupt one byte in the framed bytes of good1 AFTER the STARTCHAR to break CRC.
    bad1 = bytearray(good1)
    assert bad1[0] == STARTCHAR
    if len(bad1) < 6:
        pytest.skip("Frame unexpectedly too short to corrupt safely")
    bad1[5] ^= 0xFF  # flip bits

    stream = bytes(bad1) + good2
    results = deframe_feed(state, stream)
    frames = _collect_ok_frames(results)

    assert any(f[0] == 0x81 and f[3:] == b"SECOND" for f in frames)
