"""Change-of-Authorization and Disconnect — RFC 5176.

This is the one place the tool acts as a RADIUS *server*: the policy server
initiates, and we listen. Everything else in this package is a client.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from . import radius as rad
from .types import ErrorCause, RadiusAttr, RadiusCode

__all__ = ["ANSWERS", "RadiusCode", "ErrorCause", "decode_request",
           "encode_response", "ack", "nak", "session_key",
           "wants_reauthentication"]

# Requests we answer, mapped to their ACK and NAK codes.
ANSWERS = {
    RadiusCode.DISCONNECT_REQUEST: (RadiusCode.DISCONNECT_ACK,
                                    RadiusCode.DISCONNECT_NAK),
    RadiusCode.COA_REQUEST: (RadiusCode.COA_ACK, RadiusCode.COA_NAK),
}


def decode_request(data: bytes, secret: bytes) -> dict:
    """Parse and authenticate an inbound CoA or Disconnect request.

    RFC 5176 Section 2.3: the Request Authenticator is computed the same way as
    an Accounting-Request — MD5 over the packet with the authenticator field
    zeroed. A request that fails this check must be silently discarded.
    """
    if len(data) < 20:
        raise ValueError("packet too short")
    code, pkt_id, length = struct.unpack_from("!BBH", data, 0)
    if code not in ANSWERS:
        raise ValueError(f"not a CoA or Disconnect request (code {code})")
    if length < 20 or length > len(data):
        raise ValueError(f"length field {length} inconsistent with {len(data)} received")

    authenticator = data[4:20]
    zeroed = data[:4] + b"\x00" * 16 + data[20:length]
    if not hmac.compare_digest(hashlib.md5(zeroed + secret).digest(), authenticator):
        raise ValueError("request authenticator mismatch — wrong shared secret")

    attrs = rad._decode_attrs(data[20:length])
    offset = rad._find_attr_offset(data[:length], RadiusAttr.MESSAGE_AUTHENTICATOR)
    if offset is not None:
        buf = bytearray(data[:length])
        buf[offset:offset + 16] = b"\x00" * 16
        expected = hmac.new(secret, bytes(buf), hashlib.md5).digest()
        if not hmac.compare_digest(expected, data[offset:offset + 16]):
            raise ValueError("Message-Authenticator mismatch")

    return {"code": code, "id": pkt_id, "authenticator": authenticator,
            "attrs": attrs,
            "by_type": {t: v for t, v in attrs}}


def encode_response(code: int, pkt_id: int, request_auth: bytes, secret: bytes,
                    attrs: list[tuple[int, bytes]] | None = None) -> bytes:
    """Build an ACK or NAK for a request we just answered."""
    attr_bytes = b""
    for attr_type, value in (attrs or []):
        attr_bytes += struct.pack("BB", attr_type, len(value) + 2) + value
    length = 20 + len(attr_bytes)
    body = struct.pack("!BBH", code, pkt_id, length) + request_auth + attr_bytes
    authenticator = hashlib.md5(body + secret).digest()
    return body[:4] + authenticator + attr_bytes


def nak(request: dict, secret: bytes, cause: ErrorCause) -> bytes:
    """NAK carrying an Error-Cause so the sender learns why."""
    _, nak_code = ANSWERS[request["code"]]
    return encode_response(nak_code, request["id"], request["authenticator"], secret,
                           [(RadiusAttr.ERROR_CAUSE, struct.pack("!I", cause))])


def ack(request: dict, secret: bytes) -> bytes:
    ack_code, _ = ANSWERS[request["code"]]
    return encode_response(ack_code, request["id"], request["authenticator"], secret)


def session_key(request: dict) -> dict:
    """Identifying attributes the sender used to name a session."""
    by = request["by_type"]
    out = {}
    if RadiusAttr.ACCT_SESSION_ID in by:
        out["acct_session_id"] = by[RadiusAttr.ACCT_SESSION_ID].decode("latin1")
    if RadiusAttr.CALLING_STATION_ID in by:
        out["mac"] = by[RadiusAttr.CALLING_STATION_ID].decode("latin1")
    if RadiusAttr.USER_NAME in by:
        out["username"] = by[RadiusAttr.USER_NAME].decode("latin1")
    return out


def wants_reauthentication(request: dict) -> bool:
    """True when a CoA-Request asks for re-authentication.

    Carried as a Cisco-AVPair (vendor 9, subtype 1) reading
    'subscriber:command=reauthenticate'.
    """
    for attr_type, value in request["attrs"]:
        if attr_type == 26 and len(value) > 6:
            vendor = struct.unpack("!I", value[:4])[0]
            if vendor == 9 and b"reauthenticate" in value:
                return True
    return False
