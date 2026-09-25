"""TEAP TLV parser/builder — RFC 9930 section 4."""

import struct

from .types import (
    TEAPTLVType,
    TEAPResultStatus,
    TEAPIdentityType,
    PACSubType,
)


def encode_tlv(tlv_type: int, mandatory: bool, value: bytes) -> bytes:
    flags_type = (tlv_type & 0x3FFF) | (0x8000 if mandatory else 0)
    return struct.pack("!HH", flags_type, len(value)) + value


def decode_tlvs(data: bytes) -> list[tuple[int, bool, bytes]]:
    tlvs = []
    offset = 0
    while offset + 4 <= len(data):
        flags_type, length = struct.unpack_from("!HH", data, offset)
        mandatory = bool(flags_type & 0x8000)
        tlv_type = flags_type & 0x3FFF
        offset += 4
        if offset + length > len(data):
            break
        value = data[offset:offset + length]
        tlvs.append((tlv_type, mandatory, value))
        offset += length
    return tlvs


# ── Typed builders ──────────────────────────────────────────

def result_tlv(status: TEAPResultStatus) -> bytes:
    return encode_tlv(TEAPTLVType.RESULT, True, struct.pack("!H", status))


def intermediate_result_tlv(status: TEAPResultStatus) -> bytes:
    return encode_tlv(TEAPTLVType.INTERMEDIATE_RESULT, True, struct.pack("!H", status))


def error_tlv(code: int) -> bytes:
    return encode_tlv(TEAPTLVType.ERROR, True, struct.pack("!I", code))


def nak_tlv(tlv_type: int, vendor_id: int = 0) -> bytes:
    """NAK a mandatory TLV this peer does not support (RFC 9930 section 4.2.5)."""
    return encode_tlv(TEAPTLVType.NAK, True, struct.pack("!IH", vendor_id, tlv_type))


def eap_payload_tlv(eap_data: bytes) -> bytes:
    return encode_tlv(TEAPTLVType.EAP_PAYLOAD, True, eap_data)


def identity_type_tlv(identity_type: TEAPIdentityType) -> bytes:
    return encode_tlv(TEAPTLVType.IDENTITY_TYPE, True, struct.pack("!H", identity_type))


# ── PAC TLV sub-parser ──────────────────────────────────────

def parse_pac_tlv(data: bytes) -> dict:
    result = {}
    offset = 0
    while offset + 4 <= len(data):
        sub_type, sub_len = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + sub_len > len(data):
            break
        sub_value = data[offset:offset + sub_len]
        if sub_type == PACSubType.PAC_KEY:
            result["pac_key"] = sub_value
        elif sub_type == PACSubType.PAC_OPAQUE:
            result["pac_opaque"] = sub_value
        elif sub_type == PACSubType.PAC_LIFETIME:
            if sub_len >= 4:
                result["pac_lifetime"] = struct.unpack("!I", sub_value[:4])[0]
        elif sub_type == PACSubType.PAC_A_ID:
            result["pac_a_id"] = sub_value
        elif sub_type == PACSubType.PAC_A_ID_INFO:
            result["pac_a_id_info"] = sub_value
        elif sub_type == PACSubType.PAC_I_ID:
            result["pac_i_id"] = sub_value
        else:
            result[f"unknown_{sub_type}"] = sub_value
        offset += sub_len
    return result
