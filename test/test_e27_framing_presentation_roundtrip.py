from __future__ import annotations

from elke27_lib.framing import DeframeState, deframe_feed, frame_build
from elke27_lib.linking import derive_pass_tempkey_with_cnonce
from elke27_lib.presentation import decrypt_schema0_envelope, encrypt_schema0_envelope


def test_encrypt_frame_deframe_decrypt_roundtrip() -> None:
    payload = b"hello e27"
    _pass8, tempkey_hex = derive_pass_tempkey_with_cnonce(
        access_code="123456",
        passphrase="example-passphrase",
        nonce="nonce123",
        cnonce="cnonce456",
        mn="E27",
        sn="001122334455",
    )
    session_key = bytes.fromhex(tempkey_hex)

    protocol, ciphertext = encrypt_schema0_envelope(
        payload=payload,
        session_key=session_key,
        src=1,
        dest=0,
        head=0,
        envelope_seq=123,
    )

    framed = frame_build(protocol_byte=protocol, data_frame=ciphertext)

    state = DeframeState()
    results = deframe_feed(state, framed)
    ok_results = [res for res in results if res.ok]

    assert len(ok_results) == 1
    frame_no_crc = ok_results[0].frame_no_crc
    assert frame_no_crc is not None

    length = frame_no_crc[1] | (frame_no_crc[2] << 8)
    assert length == len(frame_no_crc) + 2

    protocol_rx = frame_no_crc[0]
    data_frame = frame_no_crc[3:]

    decrypted = decrypt_schema0_envelope(
        protocol_byte=protocol_rx,
        ciphertext=data_frame,
        session_key=session_key,
    )

    assert decrypted.payload == payload
    assert decrypted.envelope_seq == 123
