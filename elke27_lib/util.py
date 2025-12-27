"""Utility functions"""

from __future__ import annotations

import ssl
from functools import cache

TLS_VERSIONS = {
    # Unfortunately M1XEP does not support auto-negotiation for TLS
    # protocol; the user code must figure out the version to use. The
    # simplest way is to configure using the connection URL (smarter would
    # be to try to connect using each of the version, except SSL lib does
    # not report TLS error, it just closes the connection, so no easy way to
    # know a different protocol version should be tried)
    "elks": ssl.TLSVersion.TLSv1,
    "elksv1_0": ssl.TLSVersion.TLSv1,
    "elksv1_2": ssl.TLSVersion.TLSv1_2,
    "elksv1_3": ssl.TLSVersion.TLSv1_3,
}


def url_scheme_is_secure(url: str) -> bool:
    """Check if the URL is one that requires SSL/TLS."""
    scheme, _dest = url.split("://")
    return scheme.startswith("elks")


@cache
def ssl_context_for_scheme(scheme: str) -> ssl.SSLContext:
    """Create an SSL context for the given scheme.

    Since ssl context is expensive to create, cache it
    for future use since we only have a few schemes.
    """
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if tls := TLS_VERSIONS.get(scheme):
        ssl_context.minimum_version = tls
        ssl_context.maximum_version = tls

    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.set_ciphers("DEFAULT:@SECLEVEL=0")

    # ssl.OP_LEGACY_SERVER_CONNECT is only available in Python 3.12a4+
    ssl_context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ssl_context


def parse_url(url: str) -> tuple[str, str, int, ssl.SSLContext | None]:
    """Parse a Elk connection string"""
    scheme, dest = url.split("://")
    host = None
    ssl_context = None
    if scheme == "elk":
        host, port = dest.split(":") if ":" in dest else (dest, "2101")
    elif TLS_VERSIONS.get(scheme):
        host, port = dest.split(":") if ":" in dest else (dest, "2601")
        ssl_context = ssl_context_for_scheme(scheme)
        scheme = "elks"
    else:
        raise ValueError(f"Invalid scheme '{scheme}'")
    return (scheme, host, int(port), ssl_context)


def pretty_const(value: str) -> str:
    """Make a constant pretty for printing in GUI"""
    words = value.split("_")
    pretty = words[0].capitalize()
    for word in words[1:]:
        pretty += " " + word.lower()
    return pretty


def calculate_crc16_checksum(w_sum: int, data_bytes: bytes | bytearray, start: int, numb: int) -> int:
    """
    CRC-16 (polynomial 0xA001, standard reflected CRC-16)

    :param w_sum: Initial CRC value
    :param data_bytes: Byte buffer (bytes or bytearray)
    :param start: Starting index
    :param numb: Number of bytes to process
    :return: 16-bit CRC value
    """
    w_sum &= 0xFFFF

    for i in range(start, start + numb):
        data = data_bytes[i] & 0xFF

        for _ in range(8):
            xor_flag = (w_sum & 1) ^ (data & 1)
            w_sum >>= 1
            if xor_flag:
                w_sum ^= 0xA001
            data >>= 1

    return w_sum & 0xFFFF

from typing import Union

#def swap_endianness(src: Union[bytes, bytearray, list[int]]) -> bytearray:
def swap_endianness(src: Union[bytes, bytearray, list[int]]) -> bytes:
    """
    Swaps the endianness of 32-bit words in a byte array.
    Processes the input in 4-byte chunks, reversing the order of bytes within each chunk.

    Raises:
        ValueError:
            - if src is None
            - if src is empty
            - if length of src is not evenly divisible by 4
    """
    if src is None:
        raise ValueError("swap_endianness: src is None")

    length = len(src)
    if length == 0:
        raise ValueError("swap_endianness: src is empty")

    if length % 4 != 0:
        raise ValueError(
            f"swap_endianness: length {length} is not divisible by 4"
        )

    # Normalize input to bytes-like
    data = src if isinstance(src, (bytes, bytearray)) else bytes(src)

    result = bytearray(length)

    for index in range(0, length, 4):
        result[index + 0] = data[index + 3]
        result[index + 1] = data[index + 2]
        result[index + 2] = data[index + 1]
        result[index + 3] = data[index + 0]

    return bytes(result)

def calculate_block_padding(length: int, block_size: int = 16) -> int:
    """
    Equivalent to JS:
        (16 - (length % 16)) & 15

    Returns the number of padding bytes needed to reach the next block boundary,
    in the range 0..block_size-1.

    Hard-fails if length is negative.
    """
    if length < 0:
        raise ValueError(f"calculate_block_padding: length must be >= 0 (got {length})")
    if block_size <= 0:
        raise ValueError(f"calculate_block_padding: block_size must be > 0 (got {block_size})")

    # For block_size=16, this matches the JS exactly:
    return (block_size - (length % block_size)) % block_size
