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
        # Re-authentication takes seconds; the sender expects a prompt ACK, so
        # the work runs as a task. Keep a reference or the loop may collect it.
        self._tasks: set = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            self._handle(data, addr)
        except Exception:
            log.exception("CoA handling failed for %s", addr)

    def _handle(self, data: bytes, addr) -> None:
        # Logged before anything else: when CoA misbehaves, the first question
        # is whether a packet arrived at all.
        kind = {40: "Disconnect-Request", 43: "CoA-Request"}.get(data[0] if data else 0,
                                                              f"code {data[0] if data else '?'}")
        log.info("%s received from %s:%s (%d bytes)", kind, addr[0], addr[1], len(data))
        database = self.factory()
        try:
            request, secret = self._authenticate(database, data, addr[0])
            if request is None:
                # Either no configured secret validates the packet, or none is
                # known for this sender. Without one there is nothing to
                # authenticate against and nothing to sign a reply with, so
                # silence is the only correct answer (RFC 5176).
                log.warning("CoA from %s not authenticated by any known secret",
                            addr[0])
                return

            session = self._session_for(database, request)
            if session is None:
                self.transport.sendto(
                    coa.nak(request, secret, ErrorCause.SESSION_CONTEXT_NOT_FOUND), addr)
                log.info("%s from %s: no matching session, NAK sent", kind, addr[0])
                return

            reauth = (request["code"] == coa.RadiusCode.COA_REQUEST
                      and coa.wants_reauthentication(request))
            session_id = session.id
            self._apply(database, session, request)

            # ACK first: it means "accepted", not "already finished".
            self.transport.sendto(coa.ack(request, secret), addr)
            log.info("%s from %s for %s: ACK sent, session now %s", kind, addr[0],
                     session.mac, session.acct_status)
            if reauth:
                self._spawn_reauth(session_id)
        finally:
            database.close()

    def _authenticate(self, database, data: bytes, sender: str):
        """Find the shared secret that validates this packet.

        Matching on source address alone is fragile: a policy server may send
        CoA from a different interface than the one its RADIUS address names.
        The address is tried first, then every other CoA-enabled server, since
        a packet only validates under the secret it was signed with.
        """
        candidates = list(database.scalars(
            select(Server).where(Server.address == sender)).all())
        candidates += [s for s in database.scalars(
            select(Server).where(Server.coa_enabled.is_(True))).all()
            if s.address != sender]

        for server in candidates:
            try:
                secret = secret_store.decrypt(server.secret_enc).encode()
            except ValueError:
                continue
            try:
                return coa.decode_request(data, secret), secret
            except ValueError:
                continue
        return None, b""

    def _spawn_reauth(self, session_id: str) -> None:
        from . import generator
        task = asyncio.create_task(
            generator.reauth_session(session_id, self.factory))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    @staticmethod
    def _session_for(database, request) -> Session | None:
        key = coa.session_key(request)
        stmt = select(Session).order_by(Session.started.desc()).limit(1)
        if "acct_session_id" in key:
            found = database.scalars(
                stmt.where(Session.acct_session_id == key["acct_session_id"])).first()
            if found:
                return found
        if "audit_session_id" in key:
            found = database.scalars(stmt.where(Session.class_blob.contains(
                key["audit_session_id"].encode().hex()))).first()
            if found:
                return found
        if "mac" in key:
            return database.scalars(
                stmt.where(Session.mac.in_(coa.mac_variants(key["mac"])))).first()
        return None

    @staticmethod
    def _apply(database, session: Session, request) -> None:
        if request["code"] == coa.RadiusCode.DISCONNECT_REQUEST:
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
