"""RADIUS accounting client — RFC 2866.

Separate from the TEAP exchange: accounting acts on a session that has already
been authenticated, using the Acct-Session-Id chosen for the Access-Request and
the Class the server returned in its Access-Accept.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from . import radius as rad
from .types import AcctStatusType, RadiusAttr, RadiusCode


@dataclass
class AcctSession:
    """What accounting needs to know about an authenticated session."""

    acct_session_id: str
    username: str
    nas_ip: str = "0.0.0.0"
    calling_station_id: str = ""
    called_station_id: str = ""
    framed_ip: str = ""
    nas_port: int = 1
    nas_port_type: int = 15
    nas_identifier: str = ""
    class_blob: bytes = b""          # echoed verbatim; ISE correlates on it
    extra_attrs: list[tuple[int, bytes]] = field(default_factory=list)


@dataclass
class AcctResult:
    success: bool
    message: str
    duration: float = 0.0


def _ip_bytes(addr: str) -> bytes:
    try:
        return socket.inet_aton(addr)
    except OSError:
        return socket.inet_aton("0.0.0.0")


def build_attrs(session: AcctSession, status: AcctStatusType,
                session_time: int = 0, input_octets: int = 0,
                output_octets: int = 0,
                terminate_cause: int = 1) -> list[tuple[int, bytes]]:
    """Attributes for one accounting record.

    Class (RFC 2865 Section 5.25) MUST be sent back unmodified when the server
    supplied one; it is how the accounting record is tied to the authentication.
    """
    attrs: list[tuple[int, bytes]] = [
        (RadiusAttr.ACCT_STATUS_TYPE, struct.pack("!I", status)),
        (RadiusAttr.ACCT_SESSION_ID, session.acct_session_id.encode()),
        (RadiusAttr.USER_NAME, session.username.encode()),
        (RadiusAttr.NAS_IP_ADDRESS, _ip_bytes(session.nas_ip)),
        (RadiusAttr.NAS_PORT, struct.pack("!I", session.nas_port)),
        (RadiusAttr.NAS_PORT_TYPE, struct.pack("!I", session.nas_port_type)),
        (RadiusAttr.ACCT_AUTHENTIC, struct.pack("!I", 1)),   # RADIUS
    ]
    if session.calling_station_id:
        attrs.append((RadiusAttr.CALLING_STATION_ID, session.calling_station_id.encode()))
    if session.called_station_id:
        attrs.append((RadiusAttr.CALLED_STATION_ID, session.called_station_id.encode()))
    if session.nas_identifier:
        attrs.append((RadiusAttr.NAS_IDENTIFIER, session.nas_identifier.encode()))
    if session.framed_ip:
        attrs.append((RadiusAttr.FRAMED_IP_ADDRESS, _ip_bytes(session.framed_ip)))
    if session.class_blob:
        attrs.append((RadiusAttr.CLASS, session.class_blob))

    if status in (AcctStatusType.STOP, AcctStatusType.INTERIM_UPDATE):
        attrs += [
            (RadiusAttr.ACCT_SESSION_TIME, struct.pack("!I", session_time)),
            (RadiusAttr.ACCT_INPUT_OCTETS, struct.pack("!I", input_octets)),
            (RadiusAttr.ACCT_OUTPUT_OCTETS, struct.pack("!I", output_octets)),
        ]
    if status == AcctStatusType.STOP:
        attrs.append((RadiusAttr.ACCT_TERMINATE_CAUSE, struct.pack("!I", terminate_cause)))

    return attrs + list(session.extra_attrs)


async def send(host: str, port: int, secret: str, session: AcctSession,
               status: AcctStatusType, *, timeout: float = 5.0, retries: int = 3,
               source_ip: str = "", pkt_id: int = 1, **counters) -> AcctResult:
    """Send one accounting record and validate the reply."""
    import time
    secret_b = secret.encode()
    attrs = build_attrs(session, status, **counters)
    packet, authenticator = rad.encode_accounting_request(pkt_id, secret_b, attrs)

    start = time.monotonic()
    try:
        reply = await rad.send_receive(host, port, secret_b, packet,
                                       timeout=timeout, retries=retries,
                                       source_ip=source_ip, expected_id=pkt_id)
    except TimeoutError as exc:
        return AcctResult(False, str(exc), time.monotonic() - start)

    duration = time.monotonic() - start
    try:
        parsed = rad.decode_response(reply, secret_b, authenticator)
    except ValueError as exc:
        return AcctResult(False, str(exc), duration)

    if parsed["code"] != RadiusCode.ACCOUNTING_RESPONSE:
        return AcctResult(False, f"unexpected RADIUS code {parsed['code']}", duration)
    return AcctResult(True, f"Accounting-Response ({status.name})", duration)
