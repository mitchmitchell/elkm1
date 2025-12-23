from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from dataclasses import dataclass
from typing import Final, Optional

from .errors import E27ErrorContext, E27ProvisioningTimeout, E27ProtocolError, E27TransportError

# Fixed IV for api_link and hello flows
API_LINK_IV: Final[bytes] = bytes(range(16))  # 00 01 02 ... 0f (Java initVectorBytes)


@dataclass(frozen=True, slots=True)
class E27Identity:
    """Identity values sent during provisioning/hello."""
    mn: str
    sn: str
    fwver: str
    hwver: str
    osver: str


@dataclass(frozen=True, slots=True)
class LinkCredentials:
    """Results of api_link provisioning."""
    linkkey_hex: str   # 16 bytes -> 32 hex chars
    linkhmac_hex: str  # observed 20 bytes -> 40 hex chars (panel-specific)


def _sha1_hex_lower(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest().lower()


def _random_cnonce_hex_lower(nbytes: int = 20) -> str:
    # Node-RED prototype used 20 bytes (40 hex chars)
    return os.urandom(nbytes).hex().lower()


def _parse_concatenated_json_objects(s: str) -> list[str]:
    """
    Panel may send multiple JSON objects back-to-back (e.g. discovery hello + LOCAL).
    Returns each top-level JSON object string.
    """
    out: list[str] = []
    depth = 0
    start = 0
    in_string = False
    escape = False

    for i, ch in enumerate(s):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                out.append(s[start : i + 1])

    if depth != 0:
        raise ValueError("Unbalanced braces in concatenated JSON stream")

    return out


def recv_cleartext_json_objects(sock: socket.socket, timeout_s: float = 5.0) -> list[dict]:
    """
    Read some bytes and parse 1..N concatenated JSON objects.

    This is used for:
    - discovery hello (ELKWC2017)
    - hello response (clear JSON)
    """
    sock.settimeout(timeout_s)
    try:
        data = sock.recv(4096)
    except socket.timeout as e:
        raise E27ProvisioningTimeout(
            "Timed out waiting for cleartext JSON from panel.",
            context=E27ErrorContext(phase="cleartext_recv"),
            cause=e,
        )
    except OSError as e:
        raise E27TransportError(
            f"Socket error receiving cleartext JSON: {e}",
            context=E27ErrorContext(phase="cleartext_recv"),
            cause=e,
        )

    if not data:
        raise E27TransportError(
            "Socket closed while waiting for cleartext JSON.",
            context=E27ErrorContext(phase="cleartext_recv"),
        )

    s = data.decode("utf-8", errors="replace").strip()
    objs: list[dict] = []
    for part in _parse_concatenated_json_objects(s):
        try:
            objs.append(json.loads(part))
        except json.JSONDecodeError as e:
            raise E27ProtocolError(
                f"Failed to decode cleartext JSON object: {e}",
                context=E27ErrorContext(phase="cleartext_json_decode"),
                cause=e,
            )
    return objs


def wait_for_discovery_nonce(sock: socket.socket, timeout_s: float = 10.0) -> str:
    """
    Wait for discovery hello containing ELKWC2017 and return nonce string.
    """
    deadline = time.monotonic() + timeout_s
    buf = bytearray()

    sock.settimeout(1.0)
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError as e:
            raise E27TransportError(
                f"Socket error waiting for discovery: {e}",
                context=E27ErrorContext(phase="discovery_recv"),
                cause=e,
            )

        if not chunk:
            raise E27TransportError(
                "Socket closed while waiting for discovery hello.",
                context=E27ErrorContext(phase="discovery_recv"),
            )

        buf.extend(chunk)
        s = buf.decode("utf-8", errors="ignore")
        if "ELKWC2017" not in s:
            continue

        objs = recv_cleartext_json_objects_from_bytes(bytes(buf))
        for obj in objs:
            if "nonce" in obj:
                return str(obj["nonce"])
        # keep waiting if ELKWC2017 present but nonce not yet parsed

    raise E27ProvisioningTimeout(
        "Timed out waiting for discovery hello (ELKWC2017) / nonce.",
        context=E27ErrorContext(phase="discovery"),
    )


def recv_cleartext_json_objects_from_bytes(data: bytes) -> list[dict]:
    s = data.decode("utf-8", errors="replace").strip()
    objs: list[dict] = []
    for part in _parse_concatenated_json_objects(s):
        if not part:
            continue
        objs.append(json.loads(part))
    return objs


def derive_pass_and_tempkey(
    *,
    access_code: str,
    passphrase: str,
    nonce: str,
    mn: str,
    sn: str,
) -> tuple[str, str]:
    """
    Matches the Node-RED prototype derivation:

      hash1 = sha1("{access_code}:{sn}:{passphrase}")
      hash2 = sha1("{sn}:{nonce}:{mn}")
      hash3 = sha1("{hash1}:{cnonce}:{hash2}")

    pass = first 8 hex chars of hash3
    tempkey = remaining hex chars of hash3 (32 hex chars -> 16 bytes AES key)
    """
    # IMPORTANT: This matches the Node-RED logic that worked against the panel.
    hash1 = _sha1_hex_lower(f"{access_code}:{sn}:{passphrase}")
    hash2 = _sha1_hex_lower(f"{sn}:{nonce}:{mn}")
    # cnonce is included later (hash3), so caller must pass it in
    raise RuntimeError("derive_pass_and_tempkey requires cnonce; use derive_pass_tempkey_with_cnonce.")


def derive_pass_tempkey_with_cnonce(
    *,
    access_code: str,
    passphrase: str,
    nonce: str,
    cnonce: str,
    mn: str,
    sn: str,
) -> tuple[str, str]:
    hash1 = _sha1_hex_lower(f"{access_code}:{sn}:{passphrase}")
    hash2 = _sha1_hex_lower(f"{sn}:{nonce}:{mn}")
    hash3 = _sha1_hex_lower(f"{hash1}:{cnonce}:{hash2}")
    return hash3[:8].lower(), hash3[8:].lower()


def build_api_link_request(
    *,
    seq: int,
    identity: E27Identity,
    pass_hex8: str,
    cnonce_hex: str,
) -> str:
    msg = {
        "seq": seq,
        "api_link": {
            "pass": pass_hex8,
            "cnonce": cnonce_hex,
            "mn": identity.mn,
            "sn": identity.sn,
            "fwver": identity.fwver,
            "hwver": identity.hwver,
            "osver": identity.osver,
        },
    }
    return json.dumps(msg, separators=(",", ":"))


def send_unframed_json(sock: socket.socket, json_text: str) -> None:
    """
    api_link request is cleartext and NOT link-framed.
    hello request is cleartext and NOT link-framed.
    """
    try:
        sock.sendall(json_text.encode("utf-8"))
    except OSError as e:
        raise E27TransportError(
            f"Socket error sending cleartext JSON: {e}",
            context=E27ErrorContext(phase="cleartext_send"),
            cause=e,
        )


def perform_api_link(
    *,
    sock: socket.socket,
    identity: E27Identity,
    access_code: str,
    passphrase: str,
    mn_for_hash: str,
    discovery_nonce: str,
    seq: int = 110,
) -> tuple[str, str, str]:
    """
    Provisioning exchange:
    - derive pass/tempkey from (access_code, passphrase, nonce, mn, sn, cnonce)
    - send api_link (clear/unframed)
    Returns: (tempkey_hex, linkkey_hex, linkhmac_hex)

    IMPORTANT: Per DDR-0020, incorrect creds may yield NO RESPONSE.
    Callers should handle E27ProvisioningTimeout and prompt user to retry.
    """
    cnonce = _random_cnonce_hex_lower(20)
    pass8, tempkey = derive_pass_tempkey_with_cnonce(
        access_code=access_code,
        passphrase=passphrase,
        nonce=discovery_nonce,
        cnonce=cnonce,
        mn=mn_for_hash,
        sn=identity.sn,
    )

    req = build_api_link_request(seq=seq, identity=identity, pass_hex8=pass8, cnonce_hex=cnonce)
    send_unframed_json(sock, req)

    # Response is framed+encrypted schema-0. We do not implement framing/crypto here;
    # the caller should pass the frame bytes into presentation/framing modules.
    return tempkey, "", ""


def parse_api_link_response_json(obj: dict) -> LinkCredentials:
    """
    Parse decrypted JSON (after ack byte stripped) for api_link response.
    """
    try:
        api_link = obj["api_link"]
        linkkey = str(api_link["enc"]).strip()
        linkhmac = str(api_link["hmac"]).strip()
        err = int(api_link.get("error_code", 0))
    except Exception as e:
        raise E27ProtocolError(
            f"Malformed api_link response JSON: {e}",
            context=E27ErrorContext(phase="api_link_parse"),
            cause=e,
        )

    if err != 0:
        # Panel *can* return error_code in decrypted json (once you got a response),
        # but wrong access/passphrase may be silent and never reach this point.
        raise E27ProtocolError(
            f"api_link returned error_code={err}",
            context=E27ErrorContext(phase="api_link_parse", detail=f"error_code={err}"),
        )

    return LinkCredentials(linkkey_hex=linkkey, linkhmac_hex=linkhmac)
