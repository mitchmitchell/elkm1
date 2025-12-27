from __future__ import annotations

from elke27_lib.linking import parse_discovery_hello_and_local


def test_parse_discovery_hello_and_local() -> None:
    data = (
        b'{"ELKWC2017":"Hello","nonce":"77274bf43c1400329c8362bacec79fe93323722c"}'
        b'{"LOCAL":"2025/12/26,18:44:00"}'
    )
    nonce, local = parse_discovery_hello_and_local(data)
    assert nonce == "77274bf43c1400329c8362bacec79fe93323722c"
    assert local == "2025/12/26,18:44:00"
