"""Session lifetime: what happens when a session's time is up.

RFC 2865 section 5.29 — Session-Timeout says how long a session may last,
Termination-Action says what to do at expiry: re-authenticate
(RADIUS-Request) or terminate. This is how a policy server expresses a
periodic reauthentication timer, so being able to drive it is how you check
such a policy actually fires.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging

from sqlalchemy import select

from teap_tester import authorization
from teap_tester.accounting import send as acct_send
from teap_tester.types import AcctStatusType, RadiusAttr

from . import secrets as secret_store
from .bulk import acct_session
from .models import Server, Session

log = logging.getLogger("teap_gui.expiry")

TICK_SECONDS = 15
ACTION_TERMINATE = 0
ACTION_REAUTHENTICATE = 1
TERMINATE_CAUSE_SESSION_TIMEOUT = 5     # RFC 2866 section 5.10

_task: asyncio.Task | None = None


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def attr(reply_attrs: dict, number: int) -> str | None:
    """Look up a reply attribute by number, whichever way it is keyed.

    A live TEAPResult keys these by int; the same data read back from the
    JSON column is keyed by string, because JSON object keys always are.
    Both reach this code, so accept both. A repeated type yields its first value.
    """
    return authorization.first(reply_attrs, number)


def from_reply(reply_attrs: dict, default_lifetime: int,
               default_action: int) -> tuple[int, int]:
    """Server-supplied lifetime and action override the job's settings."""
    lifetime, action = default_lifetime, default_action
    raw = attr(reply_attrs, RadiusAttr.SESSION_TIMEOUT)
    if raw:
        try:
            lifetime = int(raw, 16)
        except ValueError:
            pass
    raw = attr(reply_attrs, RadiusAttr.TERMINATION_ACTION)
    if raw:
        try:
            action = int(raw, 16)
        except ValueError:
            pass
    return lifetime, action


async def _expire_one(database, row: Session, factory) -> str:
    """Apply the termination action to one expired session."""
    from . import generator

    if row.termination_action == ACTION_REAUTHENTICATE:
        ok = await generator.reauth_session(row.id, factory)
        fresh = database.get(Session, row.id)
        if fresh is not None:
            fresh.expires_at = (_now() + dt.timedelta(seconds=fresh.lifetime_seconds)
                                if ok and fresh.lifetime_seconds else None)
            database.commit()
        return "reauthenticated" if ok else "reauth-failed"

    server = database.get(Server, row.server_id)
    if server is not None and row.acct_status in ("started", "reauthenticated"):
        acct = acct_session(row)
        await acct_send(server.address, server.acct_port,
                        secret_store.decrypt(server.secret_enc), acct,
                        AcctStatusType.STOP,
                        session_time=row.acct_session_time,
                        input_octets=row.acct_session_time * 128,
                        output_octets=row.acct_session_time * 256,
                        terminate_cause=TERMINATE_CAUSE_SESSION_TIMEOUT)
    row.acct_status = "expired"
    row.expires_at = None
    row.changed = dt.datetime.now(dt.timezone.utc)
    database.commit()
    return "expired"


async def _tick(factory) -> int:
    database = factory()
    handled = 0
    try:
        due = database.scalars(
            select(Session)
            .where(Session.expires_at.is_not(None))
            .where(Session.expires_at <= _now())).all()
        for row in due:
            try:
                outcome = await _expire_one(database, row, factory)
                log.info("session %s: %s", row.mac, outcome)
                handled += 1
            except Exception:
                log.exception("expiry failed for %s", row.mac)
    finally:
        database.close()
    return handled


async def _loop(factory) -> None:
    while True:
        await asyncio.sleep(TICK_SECONDS)
        try:
            await _tick(factory)
        except Exception:
            log.exception("expiry tick failed")


def start(factory) -> None:
    """Always running: sessions only expire if they were given a lifetime."""
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop(factory))


def stop() -> None:
    global _task
    if _task is not None:
        _task.cancel()
        _task = None
