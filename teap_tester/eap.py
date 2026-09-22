"""EAP frame parsing + TEAP framing (flags, fragmentation)."""

from __future__ import annotations

import struct

from .types import (
    EAPCode,
    EAPType,
    TEAP_FLAG_L,
    TEAP_FLAG_M,
    TEAP_FLAG_S,
    TEAP_VERSION,
    TEAP_VERSION_MASK,
)


def encode_eap(code: int, pkt_id: int, type_id: int | None = None,
               data: bytes = b"") -> bytes:
    if code in (EAPCode.SUCCESS, EAPCode.FAILURE):
        return struct.pack("!BBH", code, pkt_id, 4)
    if type_id is None:
        raise ValueError("EAP type required for Request/Response")
    payload = struct.pack("B", type_id) + data
    length = 4 + len(payload)
    return struct.pack("!BBH", code, pkt_id, length) + payload


def decode_eap(data: bytes) -> dict:
    if len(data) < 4:
        raise ValueError("EAP packet too short")
    code, pkt_id, length = struct.unpack_from("!BBH", data, 0)
    result = {"code": code, "id": pkt_id, "length": length}
    if code in (EAPCode.SUCCESS, EAPCode.FAILURE):
        result["type"] = None
        result["payload"] = b""
        return result
    if len(data) >= 5:
        result["type"] = data[4]
        result["payload"] = data[5:length] if length > 5 else b""
    else:
        result["type"] = None
        result["payload"] = b""
    return result


def encode_identity_response(pkt_id: int, identity: str) -> bytes:
    return encode_eap(EAPCode.RESPONSE, pkt_id, EAPType.IDENTITY, identity.encode())


def encode_teap_response(pkt_id: int, flags: int, data: bytes = b"") -> bytes:
    flags_byte = (flags & 0xF8) | (TEAP_VERSION & TEAP_VERSION_MASK)
    return encode_eap(EAPCode.RESPONSE, pkt_id, EAPType.TEAP,
                      struct.pack("B", flags_byte) + data)


def encode_teap_response_with_length(pkt_id: int, flags: int,
                                      total_length: int, data: bytes) -> bytes:
    flags_byte = (flags | TEAP_FLAG_L) & 0xF8 | (TEAP_VERSION & TEAP_VERSION_MASK)
    return encode_eap(EAPCode.RESPONSE, pkt_id, EAPType.TEAP,
                      struct.pack("!BI", flags_byte, total_length) + data)


def decode_teap_request(payload: bytes) -> dict:
    if not payload:
        raise ValueError("Empty TEAP payload")
    flags_byte = payload[0]
    result = {
        "flags": flags_byte,
        "length_included": bool(flags_byte & TEAP_FLAG_L),
        "more_fragments": bool(flags_byte & TEAP_FLAG_M),
        "start": bool(flags_byte & TEAP_FLAG_S),
        "version": flags_byte & TEAP_VERSION_MASK,
    }
    offset = 1
    if result["length_included"]:
        if len(payload) < 5:
            raise ValueError("TEAP L flag set but no length field")
        result["total_length"] = struct.unpack_from("!I", payload, 1)[0]
        offset = 5
    else:
        result["total_length"] = None

    result["data"] = payload[offset:]
    return result


class FragmentAssembler:
    """Reassemble fragmented TEAP messages from the server."""

    def __init__(self):
        self._buffer = bytearray()
        self._total_length = 0
        self._assembling = False

    def feed(self, teap: dict) -> bytes | None:
        if teap["start"]:
            self._buffer.clear()
            self._assembling = False
            return None

        if teap["length_included"] and teap["more_fragments"]:
            self._buffer = bytearray(teap["data"])
            self._total_length = teap["total_length"]
            self._assembling = True
            return None

        if self._assembling:
            self._buffer.extend(teap["data"])
            if teap["more_fragments"]:
                return None
            self._assembling = False
            return bytes(self._buffer)

        return teap["data"]

    @property
    def needs_ack(self) -> bool:
        return self._assembling
