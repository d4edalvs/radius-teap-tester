"""UDP listener for inbound CoA and Disconnect requests (RFC 5176).

The policy server initiates these, so unlike everything else here the app has
to hold a socket open and answer. Sessions are matched on the identifiers the
sender supplies — normally Acct-Session-Id, falling back to the endpoint MAC.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging

from sqlalchemy import select

from teap_tester import coa
from teap_tester.types import ErrorCause

from . import secrets as secret_store
from .models import Server, Session

log = logging.getLogger("teap_gui.coa")
DEFAULT_PORT = 3799


class _Protocol(asyncio.DatagramProtocol):

    def __init__(self, factory):
        self.factory = factory
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            self._handle(data, addr)
        except Exception:
            log.exception("CoA handling failed for %s", addr)

    def _handle(self, data: bytes, addr) -> None:
        database = self.factory()
        try:
            server = self._server_for(database, addr[0])
            if server is None:
                # No shared secret for this sender, so no way to authenticate
                # the request and no way to sign a reply. Silence is correct.
                log.warning("CoA from unknown sender %s ignored", addr[0])
                return
            secret = secret_store.decrypt(server.secret_enc).encode()

            try:
                request = coa.decode_request(data, secret)
            except ValueError as exc:
                log.warning("CoA from %s rejected: %s", addr[0], exc)
                return

            session = self._session_for(database, request)
            if session is None:
                self.transport.sendto(
                    coa.nak(request, secret, ErrorCause.SESSION_CONTEXT_NOT_FOUND), addr)
                return

            self._apply(database, session, request)
            self.transport.sendto(coa.ack(request, secret), addr)
        finally:
            database.close()

    @staticmethod
    def _server_for(database, address: str) -> Server | None:
        return database.scalars(
            select(Server).where(Server.address == address).limit(1)).first()

    @staticmethod
    def _session_for(database, request) -> Session | None:
        key = coa.session_key(request)
        stmt = select(Session).order_by(Session.started.desc()).limit(1)
        if "acct_session_id" in key:
            found = database.scalars(
                stmt.where(Session.acct_session_id == key["acct_session_id"])).first()
            if found:
                return found
        if "mac" in key:
            return database.scalars(stmt.where(Session.mac == key["mac"])).first()
        return None

    @staticmethod
    def _apply(database, session: Session, request) -> None:
        from teap_tester.types import RadiusCode
        if request["code"] == RadiusCode.DISCONNECT_REQUEST:
            session.acct_status = "disconnected"
        elif coa.wants_reauthentication(request):
            session.acct_status = "reauth-requested"
        else:
            session.acct_status = "coa-applied"
        session.changed = dt.datetime.now(dt.timezone.utc)
        database.commit()


async def start(factory, port: int = DEFAULT_PORT):
    """Bind the listener. Returns the transport, or None if the port is taken."""
    loop = asyncio.get_running_loop()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(factory), local_addr=("0.0.0.0", port))
        log.info("CoA listener on udp/%d", port)
        return transport
    except OSError as exc:
        log.warning("CoA listener not started on udp/%d: %s", port, exc)
        return None
