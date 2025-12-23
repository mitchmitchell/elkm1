"""
elkm1.elke27_lib.linking

E27 discovery/link/hello helpers derived from the Node-RED prototype.

Provides:
- parse_concatenated_json_objects: split back-to-back JSON objects
- prepare_api_link: derive sn from outbound NIC MAC, generate cnonce, compute SHA1 chain,
  build api_link JSON bytes, return tempkey/pass for decrypting api_link response.
- build_hello_request_json: build clear hello request JSON bytes

Node-RED equivalence:
- Discovery: parse {"ELKWC2017":"Hello","nonce":"..."}
- cnonce: 20 random bytes -> hex lowercase
- hash1 = sha1("accesscode:sn:passphrase").lower()
- hash2 = sha1("sn:nonce:mn").lower()
- hash3 = sha1(f"{hash1}:{cnonce}:{hash2}").lower()
- pass = hash3[:8]
- tempkey = hash3[8:]  (32 hex chars / 16 bytes)
"""

from __future__ import annotations

import hashlib
import json
import secrets
import socket
from dataclasses import dataclass
from typing import List, Optional


class E27LinkError(ValueError):
    """Raised when E27 linking/discovery inputs are invalid."""


def parse_concatenated_json_objects(text: str) -> List[str]:
    """
    Parse a string that may contain multiple JSON objects concatenated back-to-back
    into a list of individual top-level JSON object strings.

    Assumptions (matches your Node-RED helper):
    - Top-level objects are {...}
    - Properly escaped strings; braces inside strings ignored
    - No top-level arrays

    Raises:
        E27LinkError if braces are unbalanced.
    """
    if text is None:
        raise E27LinkError("parse_concatenated_json_objects: text is None")
    s = text.strip()
    if not s:
        return []

    result: List[str] = []
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
                result.append(s[start : i + 1])

    if depth != 0:
        raise E27LinkError("parse_concatenated_json_objects: unbalanced braces in input")

    return result


def _sha1_hex_lower(msg: str) -> str:
    return hashlib.sha1(msg.encode("utf-8")).hexdigest().lower()


def _derive_outbound_local_ip(panel_host: str) -> str:
    """
    Determine the local IP used to route traffic to the panel host.
    Uses a UDP connect trick (no packet sent).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((panel_host, 1))
            return s.getsockname()[0]
    except Exception as e:
        raise E27LinkError(f"derive outbound local IP failed for {panel_host!r}: {e}") from e


def _derive_sn_from_outbound_mac(panel_host: str) -> str:
    """
    DDR-0014: derive client sn from outbound interface MAC, formatted as uppercase hex no separators.
    Best-effort implementation:
      - Determine outbound local IP to panel_host
      - Find interface owning that IP and return its MAC

    Requires psutil for deterministic interface MAC. Falls back to uuid.getnode() with warning semantics.
    """
    local_ip = _derive_outbound_local_ip(panel_host)

    # Try psutil for correct interface MAC
    try:
        import psutil  # type: ignore

        af_link = getattr(psutil, "AF_LINK", None)
        if af_link is None:
            # Windows uses psutil.AF_LINK too, but keep fallback safe.
            af_link = getattr(socket, "AF_PACKET", None)

        for ifname, addrs in psutil.net_if_addrs().items():
            has_ip = any(getattr(a, "family", None) == socket.AF_INET and getattr(a, "address", None) == local_ip for a in addrs)
            if not has_ip:
                continue

            # Find MAC on that interface
            for a in addrs:
                fam = getattr(a, "family", None)
                addr = getattr(a, "address", None)
                if addr and (fam == af_link or str(fam) == str(af_link)):
                    mac = addr
                    sn = mac.replace(":", "").replace("-", "").upper()
                    if len(sn) >= 12:
                        return sn
    except Exception:
        # Fall through to uuid.getnode()
        pass

    # Fallback: uuid.getnode() returns 48-bit MAC or random; still deterministic enough for smoketest
    import uuid

    node = uuid.getnode()
    sn = f"{node:012X}"
    return sn


@dataclass(frozen=True)
class LinkPrep:
    request_json_bytes: bytes
    tempkey_hex: str
    pass_hex: str
    cnonce_hex: str
    sn: str
    mn: str
    fwver: str
    hwver: str
    osver: str


def prepare_api_link(
    *,
    panel_host: str,
    access_code: str,
    passphrase: str,
    mn: str,
    panel_nonce_hex: str,
    sn: Optional[str] = None,
    fwver: str = "0.0.1",
    hwver: str = "0.0.1",
    osver: str = "0.0.1",
    json_seq: int = 110,
) -> LinkPrep:
    """
    Prepare the clear api_link request and compute tempkey/pass required to decrypt the api_link response.

    Args:
        panel_host: panel IP/hostname (used for outbound MAC derivation if sn not provided)
        access_code: access code (HA1 input)
        passphrase: passphrase (HA1 input)
        mn: model number / mn (HA2 input)
        panel_nonce_hex: panel-provided nonce from ELKWC2017 discovery hello (lowercase hex)
        sn: optional override; if not supplied derives from outbound interface MAC
        fwver/hwver/osver: client version strings (mirrors Node-RED defaults)
        json_seq: JSON-level seq field (not envelope seq)

    Returns:
        LinkPrep containing api_link request JSON bytes and tempkey/pass/nonce.

    Raises:
        E27LinkError for invalid input.
    """
    if not panel_host:
        raise E27LinkError("prepare_api_link: panel_host is required")
    if not access_code:
        raise E27LinkError("prepare_api_link: access_code is required")
    if not passphrase:
        raise E27LinkError("prepare_api_link: passphrase is required")
    if not mn:
        raise E27LinkError("prepare_api_link: mn is required")
    if not panel_nonce_hex or not isinstance(panel_nonce_hex, str):
        raise E27LinkError("prepare_api_link: panel_nonce_hex is required")
    nonce = panel_nonce_hex.strip().lower()
    if len(nonce) < 8:
        raise E27LinkError(f"prepare_api_link: panel_nonce_hex looks too short: {nonce!r}")

    if sn is None:
        sn_val = _derive_sn_from_outbound_mac(panel_host)
    else:
        sn_val = sn.strip().upper()
        if not sn_val:
            raise E27LinkError("prepare_api_link: sn override provided but empty")

    # 20 random bytes -> 40 hex chars lowercase
    cnonce_hex = secrets.token_bytes(20).hex()

    # Hash chain derived from Node-RED
    hash1 = _sha1_hex_lower(f"{access_code}:{sn_val}:{passphrase}")
    hash2 = _sha1_hex_lower(f"{sn_val}:{nonce}:{mn}")
    hash3 = _sha1_hex_lower(f"{hash1}:{cnonce_hex}:{hash2}")

    pass_hex = hash3[:8].lower()
    tempkey_hex = hash3[8:].lower()  # 32 hex chars (16 bytes)

    linkmsg = {
        "seq": int(json_seq),
        "api_link": {
            "pass": pass_hex,
            "cnonce": cnonce_hex,
            "mn": str(mn),
            "sn": str(sn_val),
            "fwver": str(fwver),
            "hwver": str(hwver),
            "osver": str(osver),
        },
    }

    request_json_bytes = json.dumps(linkmsg, separators=(",", ":")).encode("utf-8")

    return LinkPrep(
        request_json_bytes=request_json_bytes,
        tempkey_hex=tempkey_hex,
        pass_hex=pass_hex,
        cnonce_hex=cnonce_hex,
        sn=sn_val,
        mn=str(mn),
        fwver=str(fwver),
        hwver=str(hwver),
        osver=str(osver),
    )


def build_hello_request_json(
    *,
    mn: str,
    sn: str,
    fwver: str,
    hwver: str,
    osver: str,
    json_seq: int = 110,
) -> bytes:
    """
    Build the clear hello request JSON, matching your Node-RED "Hello Sequence - OUT".

    Payload:
      {"seq":110,"hello":{"mn":...,"sn":...,"fwver":...,"hwver":...,"osver":...}}
    """
    if not mn:
        raise E27LinkError("build_hello_request_json: mn is required")
    if not sn:
        raise E27LinkError("build_hello_request_json: sn is required")

    hellomsg = {
        "seq": int(json_seq),
        "hello": {
            "mn": str(mn),
            "sn": str(sn),
            "fwver": str(fwver),
            "hwver": str(hwver),
            "osver": str(osver),
        },
    }
    return json.dumps(hellomsg, separators=(",", ":")).encode("utf-8")
