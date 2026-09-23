"""RADIUS UDP client — packet encode/decode, async send/recv."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import struct

from .types import RadiusAttr


def encode_request(code: int, pkt_id: int, authenticator: bytes,
                   secret: bytes, attrs: list[tuple[int, bytes]]) -> bytes:
    attr_bytes = b""
    for attr_type, attr_value in attrs:
        if attr_type == RadiusAttr.EAP_MESSAGE:
            for chunk in _split_eap(attr_value):
                attr_bytes += struct.pack("BB", RadiusAttr.EAP_MESSAGE, len(chunk) + 2) + chunk
        else:
            attr_bytes += struct.pack("BB", attr_type, len(attr_value) + 2) + attr_value

    length = 20 + len(attr_bytes)
    header = struct.pack("!BBH", code, pkt_id, length) + authenticator
    packet = header + attr_bytes

    if RadiusAttr.MESSAGE_AUTHENTICATOR in [a[0] for a in attrs]:
        return packet

    msg_auth_placeholder = b"\x00" * 16
    msg_auth_attr = struct.pack("BB", RadiusAttr.MESSAGE_AUTHENTICATOR, 18) + msg_auth_placeholder
    length += 18
    header = struct.pack("!BBH", code, pkt_id, length) + authenticator
    packet = header + attr_bytes + msg_auth_attr

    msg_auth = hmac.new(secret, packet, hashlib.md5).digest()
    packet = packet[:-16] + msg_auth
    return packet


def decode_response(data: bytes, secret: bytes,
                    request_auth: bytes, verify: bool = True) -> dict:
    if len(data) < 20:
        raise ValueError("RADIUS packet too short")

    code, pkt_id, length = struct.unpack_from("!BBH", data, 0)
    if length < 20 or length > len(data):
        raise ValueError(f"RADIUS length field {length} inconsistent with {len(data)} received")
    authenticator = data[4:20]
    attrs = _decode_attrs(data[20:length])

    if verify:
        _verify_message_authenticator(data[:length], secret, request_auth)
        _verify_response_authenticator(data[:length], secret, request_auth)

    eap_chunks = []
    state = None
    for attr_type, attr_value in attrs:
        if attr_type == RadiusAttr.EAP_MESSAGE:
            eap_chunks.append(attr_value)
        elif attr_type == RadiusAttr.STATE:
            state = attr_value

    return {
        "code": code,
        "id": pkt_id,
        "authenticator": authenticator,
        "eap_message": b"".join(eap_chunks) if eap_chunks else None,
        "state": state,
        "attrs": attrs,
    }


def _verify_response_authenticator(packet: bytes, secret: bytes,
                                   request_auth: bytes) -> None:
    """RFC 2865 Section 3: ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attrs+Secret)."""
    expected = hashlib.md5(
        packet[:4] + request_auth + packet[20:] + secret
    ).digest()
    if not hmac.compare_digest(expected, packet[4:20]):
        raise ValueError("RADIUS Response Authenticator mismatch — "
                         "wrong shared secret or spoofed reply")


def _verify_message_authenticator(packet: bytes, secret: bytes,
                                  request_auth: bytes) -> None:
    """RFC 3579 Section 3.2: HMAC-MD5 over the packet with Message-Authenticator
    zeroed and the Authenticator field set to the Request Authenticator."""
    offset = _find_attr_offset(packet, RadiusAttr.MESSAGE_AUTHENTICATOR)
    if offset is None:
        return  # not present; nothing to check
    received = packet[offset:offset + 16]
    buf = bytearray(packet)
    buf[4:20] = request_auth
    buf[offset:offset + 16] = b"\x00" * 16
    expected = hmac.new(secret, bytes(buf), hashlib.md5).digest()
    if not hmac.compare_digest(expected, received):
        raise ValueError("RADIUS Message-Authenticator mismatch — "
                         "wrong shared secret or tampered reply")


def _find_attr_offset(packet: bytes, wanted: int) -> int | None:
    """Offset of the given attribute's value within the full packet, or None."""
    offset = 20
    while offset + 2 <= len(packet):
        attr_type = packet[offset]
        attr_len = packet[offset + 1]
        if attr_len < 2 or offset + attr_len > len(packet):
            return None
        if attr_type == wanted:
            return offset + 2
        offset += attr_len
    return None


def _split_eap(data: bytes, max_chunk: int = 253) -> list[bytes]:
    return [data[i:i + max_chunk] for i in range(0, len(data), max_chunk)]


def _decode_attrs(data: bytes) -> list[tuple[int, bytes]]:
    attrs = []
    offset = 0
    while offset + 2 <= len(data):
        attr_type = data[offset]
        attr_len = data[offset + 1]
        if attr_len < 2 or offset + attr_len > len(data):
            break
        attr_value = data[offset + 2:offset + attr_len]
        attrs.append((attr_type, attr_value))
        offset += attr_len
    return attrs


def parse_attribute_spec(spec: str) -> tuple[int, bytes]:
    """Parse one TYPE=VALUE attribute spec.

    VALUE is text, or 0x-prefixed hex for binary. Raises ValueError so callers
    can present the problem however suits them.
    """
    if "=" not in spec:
        raise ValueError(f"attribute {spec!r} is not TYPE=VALUE")
    raw_type, _, value = spec.partition("=")
    try:
        attr_type = int(raw_type, 0)
    except ValueError:
        raise ValueError(f"attribute type {raw_type!r} is not a number") from None
    if not 1 <= attr_type <= 255:
        raise ValueError(f"attribute type {attr_type} out of range 1-255")
    if value.startswith("0x"):
        try:
            data = bytes.fromhex(value[2:])
        except ValueError:
            raise ValueError(f"attribute {spec!r} has invalid hex") from None
    else:
        data = value.encode()
    if len(data) > 253:
        raise ValueError(f"attribute {attr_type} value exceeds 253 octets")
    return attr_type, data


def make_authenticator() -> bytes:
    return os.urandom(16)


class _RadiusProtocol(asyncio.DatagramProtocol):

    def __init__(self, expected_id: int | None = None):
        self.response: asyncio.Future | None = None
        self.transport: asyncio.DatagramTransport | None = None
        self.expected_id = expected_id

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.expected_id is not None and (len(data) < 2 or data[1] != self.expected_id):
            return  # not our reply (stray, duplicate, or spoofed) — keep waiting
        if self.response and not self.response.done():
            self.response.set_result(data)

    def error_received(self, exc):
        if self.response and not self.response.done():
            self.response.set_exception(exc)

    def connection_lost(self, exc):
        if self.response and not self.response.done():
            self.response.set_exception(exc or ConnectionError("Connection lost"))


async def send_receive(host: str, port: int, secret: bytes, packet: bytes,
                       timeout: float = 5.0, retries: int = 3,
                       source_ip: str = "", expected_id: int | None = None) -> bytes:
    loop = asyncio.get_running_loop()
    local_addr = (source_ip, 0) if source_ip else None
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _RadiusProtocol(expected_id), remote_addr=(host, port),
        local_addr=local_addr
    )
    try:
        for attempt in range(retries):
            protocol.response = loop.create_future()
            transport.sendto(packet)
            try:
                data = await asyncio.wait_for(protocol.response, timeout=timeout)
                return data
            except asyncio.TimeoutError:
                if attempt == retries - 1:
                    raise TimeoutError(f"RADIUS server {host}:{port} not responding after {retries} attempts")
    finally:
        transport.close()
