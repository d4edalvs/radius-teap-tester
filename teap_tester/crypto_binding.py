"""Crypto-Binding computation — S-IMCK, CMK, Compound MAC per RFC 7170 §5.2."""

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
    """Compute IMCK[j] from S-IMCK[j-1] and IMSK.

    RFC 7170 Section 5.2:
      IMCK[j] = TLS-PRF(S-IMCK[j-1], "Inner Methods Compound Keys", IMSK[j], 60)
      S-IMCK[j] = first 40 octets of IMCK[j]
      CMK[j] = last 20 octets of IMCK[j]
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


# ── Crypto-Binding TLV — RFC 7170 Section 4.2.13 ───────────
#
# Value layout (76 bytes):
#   [0]     Reserved
#   [1]     Version
#   [2]     Received Version
#   [3]     Flags[4 bits] | SubType[4 bits]
#             Flags: bit0=EMSK, bit1=MSK, 3=Both
#             SubType: 0=Request, 1=Response
#   [4:36]  Nonce (32 bytes)
#   [36:56] EMSK Compound MAC (20 bytes)
#   [56:76] MSK Compound MAC (20 bytes)
#
# MAC buffer (RFC 7170 Section 5.3, BUFFER items 1-4):
#   - Full Crypto-Binding TLV (4-byte header + 76-byte value = 80 bytes)
#     with BOTH MAC fields zeroed
#   - EAP type byte (0x37 = 55 = TEAP)
#   - Server outer TLVs (if any)
#   - Peer outer TLVs (if any)
#
# MAC function: RFC 7170 Section 5.3 — the MAC negotiated in TLS 1.2, i.e.
#               HMAC with the cipher suite hash, truncated to the 20-octet field


def build_crypto_binding_response(server_cb_value: bytes, cmk: bytes,
                                   hash_alg: str = "sha384",
                                   server_outer_tlvs: bytes = b"",
                                   peer_outer_tlvs: bytes = b"",
                                   emsk_cmk: bytes = b"") -> bytes:
    """Build a 76-byte Crypto-Binding response from the server's request."""
    value = bytearray(server_cb_value[:76])

    # Flags (high nibble) declare which Compound MACs this response actually
    # carries, per RFC 7170 Section 4.2.13: 1 = EMSK, 2 = MSK, 3 = both.
    # Sub-Type (low nibble) = 1, Binding Response.
    flags = 0x3 if emsk_cmk else 0x2
    value[3] = (flags << 4) | 0x01

    # Nonce: copy server nonce, set LSbit to 1 for response
    value[4 + 31] = value[4 + 31] | 0x01

    # Zero both MAC fields for computation
    value[36:56] = b"\x00" * 20  # EMSK MAC
    value[56:76] = b"\x00" * 20  # MSK MAC

    # MAC buffer: CB TLV (hdr+value) + EAP type + server outer TLVs + peer outer TLVs
    tlv_header = struct.pack("!HH", 0x8000 | 12, 76)
    mac_buffer = (tlv_header + bytes(value)
                  + struct.pack("B", EAP_TYPE_TEAP)
                  + server_outer_tlvs + peer_outer_tlvs)

    # RFC 7170 Section 5.3 item 1: both MAC fields zeroed for either computation
    msk_mac = hmac.new(cmk, mac_buffer, hash_alg).digest()[:20]
    emsk_mac = hmac.new(emsk_cmk, mac_buffer, hash_alg).digest()[:20] if emsk_cmk else b"\x00" * 20

    value[36:56] = emsk_mac
    value[56:76] = msk_mac
    return bytes(value)


def parse_crypto_binding(value: bytes) -> dict:
    """Parse a received Crypto-Binding TLV value (76 bytes)."""
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
