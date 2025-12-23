"""
elkm1.elke27_lib.framing

E27 link-layer framing/deframing (stream-safe), derived from the Node-RED prototype.

Key behaviors (1:1 with your Node-RED "Message Link Layer - IN"):
- STARTCHAR = 0x7E
- Escape rule:
    - If STARTCHAR is seen, set "escaping" flag.
    - If next byte is 0x00, treat as escaped literal STARTCHAR (0x7E) in the data stream.
    - If next byte is non-zero, it is ALWAYS the start of a NEW message and is the PROTOCOL byte.
      Any prior partial message is abandoned (hard resync).
- Message buffer is built WITHOUT STARTCHAR, and includes:
    [0]=protocol, [1..2]=length (LE), followed by (length-3) bytes of data+CRC.
- CRC check: CRC remainder over the full message (protocol..crc) must be 0.
- Output of deframer: frame_no_crc = inputBuffer[0 : length-2]
  (CRC stripped, STARTCHAR omitted; protocol+length retained).

Enhancements vs Node-RED:
- Streaming: maintains state across feed() calls.
- Returns multiple results per chunk.
- Continues scanning after errors (resync logic).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .util import calculate_crc16_checksum  # you said you already added this


STARTCHAR: int = 0x7E
DATA_BUS_IN_BUFFER_SIZE: int = 1024
MIN_MESSAGE_SIZE: int = 0  # per Node-RED StaticData; can be tightened later


class LinkState(Enum):
    WAIT_START = 1
    WAIT_LENGTH = 2
    WAIT_DATA = 3


@dataclass
class DeframeResult:
    ok: bool
    frame_no_crc: Optional[bytes] = None
    error: Optional[str] = None


@dataclass
class DeframeState:
    escaping: bool = False
    rcv_state: LinkState = LinkState.WAIT_START
    input_buf: bytearray = field(default_factory=bytearray)
    input_index: int = 0
    expected_len: int = 0  # msglength in Node-RED (protocol..crc total length)


def _crc_remainder_zero(buf: bytearray, length: int) -> bool:
    # Node-RED: 0 == calculateCRC16Checksum(0, inputBuffer, 0, msglength)
    return calculate_crc16_checksum(0, buf, 0, length) == 0


def _reset_message(state: DeframeState) -> None:
    state.input_buf.clear()
    state.input_index = 0
    state.expected_len = 0
    state.rcv_state = LinkState.WAIT_START
    # NOTE: do not touch state.escaping here; caller manages it.


def deframe_feed(state: DeframeState, chunk: bytes) -> List[DeframeResult]:
    """
    Feed raw TCP bytes into the streaming deframer.

    Returns:
        A list of DeframeResult. Results may include multiple valid frames and/or errors.

    Errors:
        - Bad CRC (CRC remainder != 0)
        - Overflow/invalid length (>= DATA_BUS_IN_BUFFER_SIZE or < MIN_MESSAGE_SIZE)

    The scanner continues after errors and attempts to resync per STARTCHAR + non-zero rule.
    """
    if state is None:
        raise ValueError("deframe_feed: state is None")
    if chunk is None:
        raise ValueError("deframe_feed: chunk is None")
    if len(chunk) == 0:
        return []

    results: List[DeframeResult] = []

    for b in chunk:
        rcvd = b & 0xFF

        # Handle startchar / escape / resync exactly as Node-RED
        if rcvd == STARTCHAR:
            state.escaping = True
            continue

        if state.escaping and rcvd != 0:
            # STARTCHAR followed by non-zero => ALWAYS start a new message
            _reset_message(state)
            state.input_buf.append(rcvd)  # protocol byte
            state.input_index = 1
            state.input_buf.append(0)     # length LSB placeholder
            state.input_buf.append(0)     # length MSB placeholder
            state.escaping = False
            state.rcv_state = LinkState.WAIT_LENGTH
            continue

        # Otherwise, if escaping and next byte was 0, it represents a literal STARTCHAR
        if state.escaping:
            # STARTCHAR followed by 0 => store STARTCHAR
            rcvd = STARTCHAR
            state.escaping = False

        # State machine
        if state.rcv_state == LinkState.WAIT_START:
            # Ignore bytes until we see STARTCHAR+nonzero which transitions above
            continue

        if state.rcv_state == LinkState.WAIT_LENGTH:
            # Fill length bytes at positions 1 and 2
            if state.input_index not in (1, 2):
                # Defensive: should never happen if we started correctly
                results.append(DeframeResult(ok=False, error="framing: internal length index out of range"))
                _reset_message(state)
                continue

            # input_buf already has size >= 3 due to placeholders
            state.input_buf[state.input_index] = rcvd
            state.input_index += 1

            if state.input_index == 3:
                # compute expected message length (protocol..crc inclusive)
                msglength = state.input_buf[1] + (state.input_buf[2] * 256)
                state.expected_len = msglength

                if msglength >= DATA_BUS_IN_BUFFER_SIZE or msglength < MIN_MESSAGE_SIZE:
                    results.append(
                        DeframeResult(
                            ok=False,
                            error=f"framing: invalid length {msglength} (min={MIN_MESSAGE_SIZE}, max<{DATA_BUS_IN_BUFFER_SIZE})",
                        )
                    )
                    _reset_message(state)
                    continue

                state.rcv_state = LinkState.WAIT_DATA

            continue

        # WAIT_DATA
        if state.rcv_state == LinkState.WAIT_DATA:
            state.input_buf.append(rcvd)
            state.input_index += 1

            if state.expected_len > 0 and state.input_index == state.expected_len:
                # Full message received; validate CRC remainder==0
                msglength = state.expected_len
                state.rcv_state = LinkState.WAIT_START

                if _crc_remainder_zero(state.input_buf, msglength):
                    # Strip CRC (last 2 bytes)
                    frame_no_crc = bytes(state.input_buf[0 : msglength - 2])
                    results.append(DeframeResult(ok=True, frame_no_crc=frame_no_crc))
                else:
                    results.append(DeframeResult(ok=False, error="framing: bad CRC (remainder != 0)"))

                _reset_message(state)
            elif state.expected_len > 0 and state.input_index > state.expected_len:
                # Should not happen; indicates length/stream desync. Reset and keep scanning.
                results.append(
                    DeframeResult(
                        ok=False,
                        error=f"framing: overrun (got {state.input_index} > expected {state.expected_len})",
                    )
                )
                _reset_message(state)

            continue

        # Unknown state (defensive)
        results.append(DeframeResult(ok=False, error="framing: unknown receive state"))
        _reset_message(state)

    return results


def frame_build(*, protocol_byte: int, data_frame: bytes) -> bytes:
    """
    Build an outbound E27 link-layer frame:
      STARTCHAR + escaped( protocol + length(LE) + data_frame + crc(LE) )

    Length field semantics match Node-RED:
      messageLength = 1 + 2 + len(data_frame) + 2   (protocol + length + data + crc)
      length is written into the unescaped buffer at offset 1.

    CRC:
      calculate_crc16_checksum(0, unescaped_without_crc, 0, unescaped_without_crc_len)
      append CRC in little-endian
    Escape:
      any 0x7E byte in the framed portion (protocol..crc) becomes 0x7E 0x00
      STARTCHAR prefix remains unescaped.
    """
    if data_frame is None:
        raise ValueError("frame_build: data_frame is None")
    if not isinstance(data_frame, (bytes, bytearray)):
        raise ValueError(f"frame_build: data_frame must be bytes-like, got {type(data_frame).__name__}")
    if not (0 <= protocol_byte <= 0xFF):
        raise ValueError(f"frame_build: protocol_byte must be 0..255, got {protocol_byte}")

    df = bytes(data_frame)

    # Total length includes CRC (as receiver expects in msglength)
    message_length = 1 + 2 + len(df) + 2

    # Build protocol + length + data (NO CRC yet)
    unescaped = bytearray(3 + len(df))
    unescaped[0] = protocol_byte & 0xFF
    unescaped[1] = message_length & 0xFF
    unescaped[2] = (message_length >> 8) & 0xFF
    unescaped[3:] = df

    # CRC over unescaped (protocol..data)
    crc = calculate_crc16_checksum(0, unescaped, 0, len(unescaped))
    framed = bytearray(len(unescaped) + 2)
    framed[: len(unescaped)] = unescaped
    framed[len(unescaped) + 0] = crc & 0xFF
    framed[len(unescaped) + 1] = (crc >> 8) & 0xFF

    # Escape framed portion and prefix STARTCHAR
    out = bytearray()
    out.append(STARTCHAR)

    for byte in framed:
        if byte == STARTCHAR:
            out.append(STARTCHAR)
            out.append(0x00)
        else:
            out.append(byte)

    return bytes(out)
