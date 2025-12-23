"""
elkm1.elke27_lib.encryption

E27 encryption primitives derived 1:1 from the working Node-RED prototype.

Key facts (from your Node-RED flow):
- Fixed IV: 00 01 02 ... 0F  (API_LINK_IV)
- swap_endianness is a 32-bit word swap (4-byte chunks)
- Schema-0 message decrypt/encrypt:
    plaintext = swap( AES_CBC_Decrypt(key, IV, swap(ciphertext)) )
    ciphertext = swap( AES_CBC_Encrypt(key, IV, swap(plaintext)) )
- Tempkey (api_link response) uses swapped key:
    key = swap(hex_to_bytes(tempkey_hex))
- SessionKey (normal schema-0) uses non-swapped key:
    key = hex_to_bytes(session_key_hex)
- Hello response fields (sk/shm) are special-case:
    key = swap(hex_to_bytes(linkkey_hex))
    plaintext = AES_CBC_Decrypt(key, IV, swap(ciphertext))
    (NO swap on plaintext)

This module does not build envelopes; that's presentation.py.
"""

from __future__ import annotations

from typing import Final

API_LINK_IV: Final[bytes] = bytes(range(16))  # 00 01 02 ... 0f (Java initVectorBytes)


class E27CryptoError(ValueError):
    """Raised when E27 crypto inputs are invalid or crypto fails."""


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert an even-length hex string to bytes with strict validation.

    Raises:
        E27CryptoError: if input is None/empty/odd-length/non-hex.
    """
    if hex_str is None:
        raise E27CryptoError("hex_to_bytes: hex_str is None")
    if not isinstance(hex_str, str):
        raise E27CryptoError(f"hex_to_bytes: hex_str must be str, got {type(hex_str).__name__}")
    s = hex_str.strip()
    if not s:
        raise E27CryptoError("hex_to_bytes: hex_str is empty")
    if len(s) % 2 != 0:
        raise E27CryptoError(f"hex_to_bytes: hex_str length must be even, got {len(s)}: {s!r}")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise E27CryptoError(f"hex_to_bytes: invalid hex string: {s!r}") from e


def swap_endianness(src: bytes | bytearray) -> bytes:
    """
    Swap the endianness of 32-bit words (4-byte chunks) in a byte string.

    IMPORTANT: For E27, this must be applied only on buffers whose length is a
    multiple of 4. We hard-fail otherwise to avoid silent crypto corruption.

    Raises:
        E27CryptoError: if src is None/empty or length not divisible by 4.
    """
    if src is None:
        raise E27CryptoError("swap_endianness: src is None")
    if len(src) == 0:
        raise E27CryptoError("swap_endianness: src is empty")
    if len(src) % 4 != 0:
        raise E27CryptoError(
            f"swap_endianness: length must be divisible by 4, got {len(src)} bytes"
        )

    out = bytearray(len(src))
    for i in range(0, len(src), 4):
        out[i + 0] = src[i + 3]
        out[i + 1] = src[i + 2]
        out[i + 2] = src[i + 1]
        out[i + 3] = src[i + 0]
    return bytes(out)


def calculate_block_padding(length: int) -> int:
    """
    E27 padding rule from Node-RED:
        (16 - (length % 16)) & 15

    Raises:
        E27CryptoError: if length is negative.
    """
    if length < 0:
        raise E27CryptoError(f"calculate_block_padding: length must be >= 0, got {length}")
    return (16 - (length % 16)) & 15


def _require_block_multiple(data: bytes, block_size: int = 16, what: str = "data") -> None:
    if data is None:
        raise E27CryptoError(f"{what}: is None")
    if len(data) == 0:
        raise E27CryptoError(f"{what}: is empty")
    if len(data) % block_size != 0:
        raise E27CryptoError(
            f"{what}: length must be a multiple of {block_size}, got {len(data)}"
        )


def _require_len(data: bytes, n: int, what: str) -> None:
    if data is None:
        raise E27CryptoError(f"{what}: is None")
    if len(data) != n:
        raise E27CryptoError(f"{what}: expected {n} bytes, got {len(data)}")


def _aes_cbc_encrypt_no_padding(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    AES-128-CBC encrypt with NO padding (plaintext length must be multiple of 16).
    """
    _require_len(key, 16, "AES key")
    _require_len(iv, 16, "AES IV")
    _require_block_multiple(plaintext, 16, "plaintext")

    # Prefer cryptography if installed (commonly available).
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        raise E27CryptoError(
            "AES backend not available. Install 'cryptography' to use AES-CBC."
        ) from e

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _aes_cbc_decrypt_no_padding(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    AES-128-CBC decrypt with NO padding (ciphertext length must be multiple of 16).
    """
    _require_len(key, 16, "AES key")
    _require_len(iv, 16, "AES IV")
    _require_block_multiple(ciphertext, 16, "ciphertext")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        raise E27CryptoError(
            "AES backend not available. Install 'cryptography' to use AES-CBC."
        ) from e

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_schema0_ciphertext(
    *,
    key: bytes,
    ciphertext: bytes,
    iv: bytes = API_LINK_IV,
) -> bytes:
    """
    Decrypt a schema-0 ciphertext payload (presentation-layer encrypted container),
    applying the E27 swap rules (swap before and after AES-CBC).

    Node-RED equivalent:
        plaintext = swap( AES_CBC_Decrypt(key, iv, swap(ciphertext)) )

    Raises:
        E27CryptoError on invalid lengths or crypto failure.
    """
    _require_len(key, 16, "schema0 key")
    _require_len(iv, 16, "schema0 IV")
    _require_block_multiple(ciphertext, 16, "schema0 ciphertext")
    swapped_ct = swap_endianness(ciphertext)
    pt = _aes_cbc_decrypt_no_padding(key, iv, swapped_ct)
    return swap_endianness(pt)


def encrypt_schema0_plaintext(
    *,
    key: bytes,
    plaintext: bytes,
    iv: bytes = API_LINK_IV,
) -> bytes:
    """
    Encrypt a schema-0 plaintext payload (presentation-layer container),
    applying the E27 swap rules.

    Inverse of decrypt_schema0_ciphertext.

    Node-RED equivalent:
        ciphertext = swap( AES_CBC_Encrypt(key, iv, swap(plaintext)) )
    """
    _require_len(key, 16, "schema0 key")
    _require_len(iv, 16, "schema0 IV")
    _require_block_multiple(plaintext, 16, "schema0 plaintext")
    swapped_pt = swap_endianness(plaintext)
    ct = _aes_cbc_encrypt_no_padding(key, iv, swapped_pt)
    return swap_endianness(ct)


def tempkey_hex_to_aes_key(tempkey_hex: str) -> bytes:
    """
    Convert tempkey_hex (32 hex chars / 16 bytes) into the AES key used to decrypt
    api_link schema-0 messages.

    Node-RED:
        key = swap(hexToBytes(tempkey_hex))
    """
    raw = hex_to_bytes(tempkey_hex)
    _require_len(raw, 16, "tempkey bytes")
    return swap_endianness(raw)


def linkkey_hex_to_aes_key(linkkey_hex: str) -> bytes:
    """
    Convert linkkey_hex into the AES key used for hello field decryption (sk/shm).

    Node-RED:
        key = swap(hexToBytes(linkkey))
    """
    raw = hex_to_bytes(linkkey_hex)
    _require_len(raw, 16, "linkkey bytes")
    return swap_endianness(raw)


def sessionkey_hex_to_aes_key(session_key_hex: str) -> bytes:
    """
    Convert sessionKey hex into the AES key used for normal schema-0 encryption/decryption.

    Node-RED uses sessionKey directly with NO swap.
    """
    raw = hex_to_bytes(session_key_hex)
    _require_len(raw, 16, "sessionKey bytes")
    return raw


def decrypt_hello_field(
    *,
    linkkey_hex: str,
    field_hex: str,
    iv: bytes = API_LINK_IV,
) -> bytes:
    """
    Decrypt a hello response encrypted field (sk or shm).

    Node-RED equivalent:
        key = swap(hexToBytes(linkkey))
        plaintext = AES_CBC_Decrypt(key, iv, swap(hexToBytes(field_hex)))
        (NO swap on plaintext)

    Returns:
        plaintext bytes (16 bytes expected for sk/shm in your flow)

    Raises:
        E27CryptoError on invalid inputs.
    """
    key = linkkey_hex_to_aes_key(linkkey_hex)
    ct = hex_to_bytes(field_hex)
    _require_block_multiple(ct, 16, "hello field ciphertext")
    swapped_ct = swap_endianness(ct)
    return _aes_cbc_decrypt_no_padding(key, iv, swapped_ct)
