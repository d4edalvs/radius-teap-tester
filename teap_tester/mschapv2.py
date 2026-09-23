"""MS-CHAPv2 for use as a TEAP inner method — RFC 2759, keys per RFC 3079.

Two primitives it needs are no longer available from the usual places: MD4 was
dropped from OpenSSL 3's default provider, and single DES only survives as
TripleDES with the key repeated. Both are implemented or adapted here rather
than depended on.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

# RFC 2759 section 8
_MAGIC1 = b"Magic server to client signing constant"
_MAGIC2 = b"Pad to make it do more than one iteration"
# RFC 3079 section 3
_MPPE_MASTER = b"This is the MPPE Master Key"
_MPPE_SEND = (b"On the client side, this is the send key; "
              b"on the server side, it is the receive key.")
_MPPE_RECV = (b"On the client side, this is the receive key; "
              b"on the server side, it is the send key.")
_SHA_PAD1 = b"\x00" * 40
_SHA_PAD2 = b"\xf2" * 40


def md4(data: bytes) -> bytes:
    """MD4 (RFC 1320). Implemented here because OpenSSL 3 no longer offers it."""
    mask = 0xFFFFFFFF
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    def rol(x, n):
        x &= mask
        return ((x << n) | (x >> (32 - n))) & mask

    for offset in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[offset:offset + 64]))
        a, b, c, d = h

        for i, s in zip(range(16), [3, 7, 11, 19] * 4):
            k = i
            f = (b & c) | (~b & d)
            a, b, c, d = d, rol(a + f + x[k], s), b, c
        for i, k in enumerate([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]):
            s = [3, 5, 9, 13][i % 4]
            f = (b & c) | (b & d) | (c & d)
            a, b, c, d = d, rol(a + f + x[k] + 0x5A827999, s), b, c
        for i, k in enumerate([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]):
            s = [3, 9, 11, 15][i % 4]
            f = b ^ c ^ d
            a, b, c, d = d, rol(a + f + x[k] + 0x6ED9EBA1, s), b, c

        h = [(v + n) & mask for v, n in zip(h, [a, b, c, d])]

    return struct.pack("<4I", *h)


def _des_key_from_7(seven: bytes) -> bytes:
    """Expand 7 key bytes to 8 by inserting the ignored parity bits."""
    b = int.from_bytes(seven, "big")
    out = bytearray(8)
    for i in range(8):
        out[i] = ((b >> (49 - 7 * i)) & 0x7F) << 1
    return bytes(out)


def _des_encrypt(block: bytes, key7: bytes) -> bytes:
    """Single DES-ECB, expressed as TripleDES with one repeated key."""
    key = _des_key_from_7(key7)
    cipher = Cipher(TripleDES(key * 3), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def nt_password_hash(password: str) -> bytes:
    """MD4 of the password in little-endian UTF-16 (RFC 2759 section 8.3)."""
    return md4(password.encode("utf-16-le"))


def challenge_hash(peer_challenge: bytes, auth_challenge: bytes,
                   username: str) -> bytes:
    """RFC 2759 section 8.2 — the first 8 octets of the SHA-1."""
    digest = hashlib.sha1(peer_challenge + auth_challenge
                          + username.encode("latin-1", "replace")).digest()
    return digest[:8]


def challenge_response(challenge: bytes, password_hash: bytes) -> bytes:
    """RFC 2759 section 8.5 — three DES operations over a 21-octet key."""
    padded = password_hash.ljust(21, b"\x00")
    return (_des_encrypt(challenge, padded[0:7])
            + _des_encrypt(challenge, padded[7:14])
            + _des_encrypt(challenge, padded[14:21]))


def generate_nt_response(auth_challenge: bytes, peer_challenge: bytes,
                         username: str, password: str) -> bytes:
    """RFC 2759 section 8.1 — the 24-octet NT-Response."""
    return challenge_response(
        challenge_hash(peer_challenge, auth_challenge, username),
        nt_password_hash(password))


def generate_authenticator_response(password: str, nt_response: bytes,
                                    peer_challenge: bytes,
                                    auth_challenge: bytes,
                                    username: str) -> str:
    """RFC 2759 section 8.7 — the S=... string the server must send back."""
    password_hash_hash = md4(nt_password_hash(password))
    digest = hashlib.sha1(password_hash_hash + nt_response + _MAGIC1).digest()
    challenge = challenge_hash(peer_challenge, auth_challenge, username)
    digest = hashlib.sha1(digest + challenge + _MAGIC2).digest()
    return "S=" + digest.hex().upper()


def _master_key(password_hash_hash: bytes, nt_response: bytes) -> bytes:
    """RFC 3079 section 3.2."""
    return hashlib.sha1(password_hash_hash + nt_response + _MPPE_MASTER).digest()[:16]


def _asymmetric_start_key(master_key: bytes, length: int, is_send: bool,
                          is_server: bool) -> bytes:
    """RFC 3079 section 3.3."""
    if is_send:
        magic = _MPPE_SEND if is_server else _MPPE_RECV
    else:
        magic = _MPPE_RECV if is_server else _MPPE_SEND
    return hashlib.sha1(master_key + _SHA_PAD1 + magic + _SHA_PAD2).digest()[:length]


def session_key(password: str, nt_response: bytes) -> bytes:
    """The 32-octet MSK the peer derives, used as the TEAP inner IMSK.

    Ordering follows the peer side of the exchange: receive key first, then
    send key, matching what a supplicant produces.
    """
    password_hash_hash = md4(nt_password_hash(password))
    master = _master_key(password_hash_hash, nt_response)
    return (_asymmetric_start_key(master, 16, is_send=False, is_server=False)
            + _asymmetric_start_key(master, 16, is_send=True, is_server=False))


def new_peer_challenge() -> bytes:
    return os.urandom(16)


# Error codes a server may return in a Failure packet (RFC 2759 section 2,
# values from the Windows error space).
ERRORS = {
    646: "restricted logon hours",
    647: "account disabled",
    648: "password expired",
    649: "no dial-in permission",
    691: "authentication failed — wrong user name or password",
    709: "error changing password",
}


def describe_failure(message: str) -> str:
    """Turn 'E=691 R=0 V=3' into something worth reading."""
    text = message.strip()
    # Search rather than tokenise: the message may be preceded by header bytes
    # that leave no separator before E=.
    found = re.search(r"E=(\d+)", text)
    if not found:
        return text
    code = int(found.group(1))
    known = ERRORS.get(code, "unknown error")
    retry = " (server allows a retry)" if re.search(r"R=1\b", text) else ""
    return f"E={code} {known}{retry}"
