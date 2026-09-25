"""Crypto-Binding — S-IMCK, CMK and Compound MAC, per RFC 9930 section 6.

RFC 9930 (TEAPv1) obsoletes RFC 7170 and fixes the derivations it left
ambiguous; section numbers below refer to it.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

EAP_TYPE_TEAP = 55  # 0x37


def tls_prf(secret: bytes, label: bytes, seed: bytes, length: int,
            hash_alg: str = "sha256") -> bytes:
    """TLS 1.2 PRF (RFC 5246 Section 5). Hash defaults to SHA-256."""
    hash_fn = getattr(hashlib, hash_alg)
    label_seed = label + seed
    a = label_seed
    output = b""
    while len(output) < length:
        a = hmac.new(secret, a, hash_fn).digest()
        output += hmac.new(secret, a + label_seed, hash_fn).digest()
    return output[:length]


def compute_imck(s_imck_prev: bytes, isk: bytes, hash_alg: str = "sha256") -> bytes:
    """Compute IMCK[j] from S-IMCK[j-1] and IMSK[j] (section 6.2.2).

      IMCK[j]   = first 60 octets of TLS-PRF(S-IMCK[j-1],
                                             "Inner Methods Compound Keys", IMSK[j])
      S-IMCK[j] = first 40 octets of IMCK[j]
      CMK[j]    = last 20 octets of IMCK[j]

    An IMSK shorter than 32 octets is zero-padded (section 6.2.1).
    """
    if len(isk) < 32:
        isk = isk + b"\x00" * (32 - len(isk))
    return tls_prf(s_imck_prev[:40], b"Inner Methods Compound Keys", isk[:32], 60,
                   hash_alg)


def compute_session_keys(session_key_seed: bytes,
                         inner_msk: bytes = b"",
                         hash_alg: str = "sha256") -> tuple[bytes, bytes]:
    """Compute S-IMCK and CMK. Returns (s_imck, cmk)."""
    s_imck_0 = session_key_seed[:40]
    if len(s_imck_0) < 40:
        s_imck_0 = s_imck_0 + b"\x00" * (40 - len(s_imck_0))
    isk = inner_msk[:32] if inner_msk else b"\x00" * 32
    imck = compute_imck(s_imck_0, isk, hash_alg)
    s_imck = imck[:40]
    cmk = imck[40:60]
    return s_imck, cmk


# ── Crypto-Binding TLV — section 4.2.13 ────────────────────
#
# Value layout (76 octets):
#   [0]     Reserved
#   [1]     Version            1 for TEAPv1
#   [2]     Received-Ver       the TEAP version negotiated, 1
#   [3]     Flags (high nibble): 1 = EMSK MAC, 2 = MSK MAC, 3 = both
#           Sub-Type (low nibble): 0 = Binding Request, 1 = Binding Response
#   [4:36]  Nonce; least significant bit 0 in a request, 1 in the response
#   [36:56] EMSK Compound MAC
#   [56:76] MSK Compound MAC
#
# Compound MAC (section 6.3) = first 20 octets of HMAC(CMK, BUFFER), HMAC
# using the hash of the negotiated TLS PRF, where BUFFER is:
#   1. the whole Crypto-Binding TLV, header included, both MAC fields zeroed
#   2. the EAP Type the other party sent in its first TEAP message: 0x37
#   3. the Outer TLVs of the server's first TEAP message
#   4. the Outer TLVs of the peer's first TEAP message

TEAP_VERSION = 1
FLAG_EMSK, FLAG_MSK = 0x1, 0x2
SUBTYPE_REQUEST, SUBTYPE_RESPONSE = 0, 1


def compound_mac(cb_value: bytes, cmk: bytes, hash_alg: str,
                 server_outer_tlvs: bytes = b"", peer_outer_tlvs: bytes = b"") -> bytes:
    """The Compound MAC over a Crypto-Binding TLV value, as section 6.3 defines.

    Used both to verify the server's request and to sign the response, so the
    two can never drift apart.
    """
    value = bytearray(cb_value[:76])
    value[36:76] = b"\x00" * 40                     # both MAC fields zeroed
    buffer = (struct.pack("!HH", 0x8000 | 12, 76) + bytes(value)
              + struct.pack("B", EAP_TYPE_TEAP) + server_outer_tlvs + peer_outer_tlvs)
    return hmac.new(cmk, buffer, hash_alg).digest()[:20]


def request_problem(parsed: dict) -> str:
    """Why a received Binding Request is invalid (section 4.2.13), or ''."""
    if parsed["version"] != TEAP_VERSION:
        return f"unknown Crypto-Binding version {parsed['version']}"
    if parsed["received_version"] != TEAP_VERSION:
        return f"Received-Ver {parsed['received_version']} is not the negotiated TEAPv1"
    if parsed["sub_type"] != SUBTYPE_REQUEST:
        return f"Sub-Type {parsed['sub_type']} where a Binding Request (0) was due"
    if parsed["flags"] not in (1, 2, 3):
        return f"invalid Flags value {parsed['flags']}"
    if parsed["nonce"][-1] & 0x01:
        return "request nonce has its least significant bit set"
    return ""


def build_crypto_binding_response(server_cb_value: bytes, cmk: bytes,
                                   hash_alg: str = "sha384",
                                   server_outer_tlvs: bytes = b"",
                                   peer_outer_tlvs: bytes = b"",
                                   emsk_cmk: bytes = b"",
                                   include_msk: bool = True) -> bytes:
    """The 76-octet Binding Response to a server's Binding Request.

    Section 6.2.4: the MSK Compound MAC is sent when the server sent one, the
    EMSK Compound MAC whenever the inner method produced an EMSK. Flags say
    exactly which are present.
    """
    flags = (FLAG_MSK if include_msk else 0) | (FLAG_EMSK if emsk_cmk else 0)
    if not flags:
        raise ValueError("no Compound MAC can be computed for this response")
    value = bytearray(server_cb_value[:76])
    value[3] = (flags << 4) | SUBTYPE_RESPONSE
    value[35] |= 0x01                                 # response nonce: LSB set
    value[36:76] = b"\x00" * 40
    mac_args = (hash_alg, server_outer_tlvs, peer_outer_tlvs)
    if emsk_cmk:
        value[36:56] = compound_mac(value, emsk_cmk, *mac_args)
    if include_msk:
        value[56:76] = compound_mac(value, cmk, *mac_args)
    return bytes(value)


def parse_crypto_binding(value: bytes) -> dict:
    """Parse a received Crypto-Binding TLV value (76 octets)."""
    if len(value) < 76:
        return {"error": f"Crypto-Binding TLV too short: {len(value)} bytes"}
    flags_subtype = value[3]
    return {
        "reserved": value[0],
        "version": value[1],
        "received_version": value[2],
        "flags": (flags_subtype >> 4) & 0x0F,
        "sub_type": flags_subtype & 0x0F,
        "nonce": bytes(value[4:36]),
        "emsk_mac": bytes(value[36:56]),
        "msk_mac": bytes(value[56:76]),
    }
