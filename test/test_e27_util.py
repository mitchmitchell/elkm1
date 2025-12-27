# test/test_e27_util.py

from __future__ import annotations
from test.helpers.trace import make_event

import ssl
import pytest

from elke27_lib.util import (
    TLS_VERSIONS,
    calculate_block_padding,
    parse_url,
    pretty_const,
    ssl_context_for_scheme,
    swap_endianness,
    url_scheme_is_secure,
)


def test_e27_util_parse_url_elk_defaults(reporter):

    scheme, host, port, ctx = parse_url("elk://example.local")

    assert scheme == "elk"
    assert host == "example.local"
    assert port == 2101
    assert ctx is None

def test_e27_util_url_scheme_is_secure(reporter):
    assert url_scheme_is_secure("elk://127.0.0.1") is False
    assert url_scheme_is_secure("elk://127.0.0.1:2101") is False
    assert url_scheme_is_secure("elks://127.0.0.1") is True
    assert url_scheme_is_secure("elksv1_2://127.0.0.1") is True


#def test_e27_util_parse_url_elk_defaults(reporter):
    scheme, host, port, ctx = parse_url("elk://example.local")
    assert scheme == "elk"
    assert host == "example.local"
    assert port == 2101
    assert ctx is None


def test_e27_util_parse_url_elk_explicit_port(reporter):
    scheme, host, port, ctx = parse_url("elk://example.local:2109")
    assert scheme == "elk"
    assert host == "example.local"
    assert port == 2109
    assert ctx is None


def test_e27_util_parse_url_elks_defaults_and_context(reporter):
    scheme, host, port, ctx = parse_url("elks://example.local")
    assert scheme == "elks"  # normalized
    assert host == "example.local"
    assert port == 2601
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


def test_e27_util_parse_url_elks_specific_version_sets_min_max(reporter):
    # Pick a specific TLS version scheme that exists on this Python build.
    # TLSv1_3 may not exist on some older OpenSSL builds; TLSv1_2 is safer.
    scheme_in = "elksv1_2"
    assert scheme_in in TLS_VERSIONS

    scheme, host, port, ctx = parse_url(f"{scheme_in}://example.local:2102")
    assert scheme == "elks"  # normalized
    assert host == "example.local"
    assert port == 2102
    assert isinstance(ctx, ssl.SSLContext)

    expected = TLS_VERSIONS[scheme_in]
    assert ctx.minimum_version == expected
    assert ctx.maximum_version == expected


def test_e27_util_parse_url_invalid_scheme_raises(reporter):
    with pytest.raises(ValueError, match="Invalid scheme"):
        parse_url("http://example.local:1234")


def test_e27_util_ssl_context_for_scheme_is_cached(reporter):
    c1 = ssl_context_for_scheme("elksv1_2")
    c2 = ssl_context_for_scheme("elksv1_2")
    assert c1 is c2  # functools.cache


def test_e27_util_pretty_const(reporter):
    assert pretty_const("ZONE_ALARM") == "Zone alarm"
    assert pretty_const("AREA_1_ARMED_AWAY") == "Area 1 armed away"
    assert pretty_const("READY") == "Ready"


def test_e27_util_swap_endianness_bytes_roundtrip(reporter):
    src = bytes.fromhex("0102030405060708")
    expected = bytes.fromhex("0403020108070605")
    assert swap_endianness(src) == expected
    # Roundtrip
    assert swap_endianness(swap_endianness(src)) == src


def test_e27_util_swap_endianness_accepts_list_of_ints(reporter):
    src = [1, 2, 3, 4, 5, 6, 7, 8]
    expected = bytes.fromhex("0403020108070605")
    assert swap_endianness(src) == expected


def test_e27_util_swap_endianness_rejects_none_empty_and_non_multiple_of_4(reporter):
    with pytest.raises(ValueError, match="src is None"):
        swap_endianness(None)

    with pytest.raises(ValueError, match="src is empty"):
        swap_endianness(b"")

    with pytest.raises(ValueError, match="not divisible by 4"):
        swap_endianness(b"\x01\x02\x03")  # length 3


def test_e27_util_calculate_block_padding_default_16(reporter):
    assert calculate_block_padding(0) == 0
    assert calculate_block_padding(1) == 15
    assert calculate_block_padding(15) == 1
    assert calculate_block_padding(16) == 0
    assert calculate_block_padding(17) == 15
    assert calculate_block_padding(31) == 1
    assert calculate_block_padding(32) == 0


def test_e27_util_calculate_block_padding_custom_block_size(reporter):
    assert calculate_block_padding(0, block_size=8) == 0
    assert calculate_block_padding(1, block_size=8) == 7
    assert calculate_block_padding(8, block_size=8) == 0
    assert calculate_block_padding(9, block_size=8) == 7
    assert calculate_block_padding(15, block_size=8) == 1
    assert calculate_block_padding(16, block_size=8) == 0


def test_e27_util_calculate_block_padding_validation(reporter):
    with pytest.raises(ValueError, match="length must be >= 0"):
        calculate_block_padding(-1)

    with pytest.raises(ValueError, match="block_size must be > 0"):
        calculate_block_padding(1, block_size=0)
