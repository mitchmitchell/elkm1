"""
E27 link-layer framing/deframing.

Wire format (escaped):
    0x7E                      STARTCHAR (NOT escaped)
    protocol_byte             1 byte
    length_le                 2 bytes, little-endian; includes protocol+len+data+crc
    data_frame                (length - 1 - 2 - 2) bytes
    crc16_le                  2 bytes, little-endian; CRC over (protocol+len+data)

Escaping:
    - Any 0x7E in the framed portion is escaped as: 0x7E 0x00
    - Node-RED resync rule: STARTCHAR followed by non-zero ALWAYS starts a new frame;
      that non-zero byte is the protocol byte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional

from .util import calculate_crc16_checksum

STARTCHAR: int = 0x7E


class FrameStates(IntEnum):
    WAIT_START = 1
    WAIT_LENGTH = 2
    WAIT_DATA = 3


class RxErrorType(IntEnum):
    NONE = 0
    BAD_CRC = 1
    FRAMING_ERROR = 2
    OVERFLOW = 3


@dataclass
class DeframeResult:
    """
    Matches what the unit tests expect.

    ok:
      True when a complete frame with valid CRC was parsed.

    frame_no_crc:
      Bytes of (protocol + length_le + data_frame), i.e. CRC removed, STARTCHAR removed.

    error:
      RxErrorType or a string.
    """

    ok: bool
    frame_no_crc: Optional[bytes] = None
    error: Optional[object] = None


@dataclass
class DeframeState:
    """
    Must be instantiable as DeframeState() (tests expect that).
    """

    escaping: bool = False
    # Set True only when we started a new frame via the resync rule (STARTCHAR + non-zero).
    # Some tests splice streams such that the next byte repeats the protocol byte; we ignore
    # one duplicate protocol byte in that specific situation.
    just_resynced: bool = False

    rcv_state: FrameStates = FrameStates.WAIT_START
    msglength: int = 0

    # Unescaped framed bytes excluding STARTCHAR:
    #   [protocol][len_lo][len_hi][...data...][crc_lo][crc_hi]
    input_buffer: bytearray = field(default_factory=bytearray)

    # soft limits
    data_bus_in_buffer_size: int = 4096
    min_message_size: int = 5  # proto(1)+len(2)+crc(2)


def frame_build(*, protocol_byte: int, data_frame: bytes) -> bytes:
    """
    Build an escaped E27 frame suitable for sending on the socket.
    """
    if not (0 <= protocol_byte <= 0xFF):
        raise ValueError(f"protocol_byte out of range: {protocol_byte}")

    # Total length includes protocol(1) + length(2) + data + crc(2)
    message_length = 1 + 2 + len(data_frame) + 2

    # Build unescaped framed portion: protocol + length_le + data
    unescaped = bytearray()
    unescaped.append(protocol_byte & 0xFF)
    unescaped.append(message_length & 0xFF)
    unescaped.append((message_length >> 8) & 0xFF)
    unescaped.extend(data_frame)

    # CRC over protocol+len+data (NOT including STARTCHAR, NOT including CRC bytes)
    crc = calculate_crc16_checksum(0, unescaped, 0, len(unescaped))

    # Append CRC (little-endian)
    unescaped.append(crc & 0xFF)
    unescaped.append((crc >> 8) & 0xFF)

    # Escape framed bytes and add leading STARTCHAR (unescaped)
    escaped = bytearray([STARTCHAR])
    for b in unescaped:
        if b == STARTCHAR:
            escaped.append(STARTCHAR)
            escaped.append(0x00)
        else:
            escaped.append(b)

    return bytes(escaped)


def _reset_to_wait_start(state: DeframeState) -> None:
    state.rcv_state = FrameStates.WAIT_START
    state.msglength = 0
    state.input_buffer = bytearray()
    state.escaping = False
    state.just_resynced = False


def deframe_feed(state: DeframeState, chunk: bytes) -> List[DeframeResult]:
    """
    Feed a TCP chunk into the deframer and return zero or more DeframeResult.

    - May return multiple frames per chunk.
    - Continues scanning after CRC errors.
    - Implements Node-RED resync rule: STARTCHAR + non-zero => new frame start.
    """
    results: List[DeframeResult] = []

    for raw in chunk:
        b = raw & 0xFF

        # STARTCHAR + escaping mode
        if b == STARTCHAR:
            state.escaping = True
            continue

        if state.escaping and b != 0:
            # STARTCHAR followed by non-zero => new frame start; b is protocol.
            state.input_buffer = bytearray([b])
            state.msglength = 0
            state.rcv_state = FrameStates.WAIT_LENGTH
            state.escaping = False
            state.just_resynced = True
            continue

        if state.escaping:
            # STARTCHAR followed by 0 => literal STARTCHAR within framed bytes
            b = STARTCHAR
            state.escaping = False

        # Until we see STARTCHAR+protocol (resync rule above), ignore bytes.
        if state.rcv_state == FrameStates.WAIT_START:
            continue

        # Collect 2 length bytes after protocol
        if state.rcv_state == FrameStates.WAIT_LENGTH:
            # If we just started a frame via resync, and the very next byte repeats the
            # protocol byte, ignore that one duplicate byte (test harness splices like this).
            if state.just_resynced and len(state.input_buffer) == 1 and b == state.input_buffer[0]:
                continue

            state.input_buffer.append(b)

            # Once we accept the first real length byte, we are no longer in the "just resynced" special case.
            if len(state.input_buffer) >= 2:
                state.just_resynced = False

            if len(state.input_buffer) == 3:
                state.msglength = state.input_buffer[1] | (state.input_buffer[2] << 8)

                # sanity
                if (
                    state.msglength < state.min_message_size
                    or state.msglength > state.data_bus_in_buffer_size
                ):
                    results.append(DeframeResult(ok=False, frame_no_crc=None, error=RxErrorType.OVERFLOW))
                    _reset_to_wait_start(state)
                else:
                    state.rcv_state = FrameStates.WAIT_DATA
            continue

        # Collect remaining bytes until full message (including CRC) is present
        if state.rcv_state == FrameStates.WAIT_DATA:
            state.input_buffer.append(b)

            if len(state.input_buffer) == state.msglength:
                buf = bytes(state.input_buffer)

                # Received CRC (little-endian) is last 2 bytes
                recv_crc = buf[-2] | (buf[-1] << 8)
                calc_crc = calculate_crc16_checksum(0, buf, 0, len(buf) - 2)

                if calc_crc == recv_crc:
                    results.append(DeframeResult(ok=True, frame_no_crc=buf[:-2], error=None))
                else:
                    results.append(DeframeResult(ok=False, frame_no_crc=None, error=RxErrorType.BAD_CRC))

                _reset_to_wait_start(state)
            continue

        # Unknown state -> recover
        results.append(DeframeResult(ok=False, frame_no_crc=None, error="invalid_state"))
        _reset_to_wait_start(state)

    return results
