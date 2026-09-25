"""Periodic Accounting Interim-Update for sessions that are accounting-started.

A real network access device sends these on a timer so the server can see a
session is still alive. RFC 2869 lets the server dictate the period with
Acct-Interim-Interval (85); when it does not, the configured value is used.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging

from sqlalchemy import select

from teap_tester.accounting import send
from teap_tester.types import AcctStatusType, RadiusAttr

from . import secrets as secret_store
from .bulk import acct_session
from .models import AppSetting, Server, Session

log = logging.getLogger("teap_gui.interim")

KEY_ENABLED = "interim_enabled"
KEY_INTERVAL = "interim_interval"
DEFAULT_INTERVAL = 300

_task: asyncio.Task | None = None


def get_setting(database, key: str, default: str) -> str:
    row = database.get(AppSetting, key)
    return row.value if row is not None else default


def set_setting(database, key: str, value: str) -> None:
    row = database.get(AppSetting, key)
    if row is None:
        database.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    database.commit()


def state(factory) -> tuple[bool, int]:
    database = factory()
    try:
        return (get_setting(database, KEY_ENABLED, "0") == "1",
                int(get_setting(database, KEY_INTERVAL, str(DEFAULT_INTERVAL))))
    finally:
        database.close()


def _interval_for(session: Session, configured: int) -> int:
    """Honour a server-supplied Acct-Interim-Interval over the configured one."""
    from .expiry import attr
    raw = attr(session.reply_attrs_json, RadiusAttr.ACCT_INTERIM_INTERVAL)
    if raw:
        try:
            return max(60, int(bytes.fromhex(raw).hex(), 16))
        except ValueError:
            pass
    return configured


async def _tick(factory, configured: int) -> int:
    """Send one Interim-Update for every accounting-started session."""
    database = factory()
    sent = 0
    try:
        rows = database.scalars(
            select(Session).where(Session.acct_status == "started")).all()
        for row in rows:
            server = database.get(Server, row.server_id)
            if server is None:
                continue
            step = _interval_for(row, configured)
            elapsed = row.acct_session_time + step
            acct = acct_session(row)
            result = await send(
                server.address, server.acct_port,
                secret_store.decrypt(server.secret_enc), acct,
                AcctStatusType.INTERIM_UPDATE,
                session_time=elapsed,
                # Counters are synthetic: this tool generates no user traffic.
                input_octets=elapsed * 128, output_octets=elapsed * 256)
            if result.success:
                row.acct_session_time = elapsed
                row.changed = dt.datetime.now(dt.timezone.utc)
                sent += 1
            database.commit()
    finally:
        database.close()
    return sent


async def _loop(factory) -> None:
    while True:
        enabled, interval = state(factory)
        if not enabled:
            return
        await asyncio.sleep(interval)
        enabled, interval = state(factory)
        if not enabled:
            return
        try:
            count = await _tick(factory, interval)
            if count:
                log.info("interim: %d update(s) sent", count)
        except Exception:
            log.exception("interim tick failed")


def start(factory) -> bool:
    """Start the timer if it is enabled and not already running.

    Must be called from the event loop, not a threadpool worker: FastAPI runs
    sync endpoints in a thread where there is no running loop.
    """
    global _task
    if _task is not None and not _task.done():
        return True
    enabled, _ = state(factory)
    if not enabled:
        return False
    _task = asyncio.create_task(_loop(factory))
    return True


def stop() -> None:
    global _task
    if _task is not None:
        _task.cancel()
        _task = None


def running() -> bool:
    return _task is not None and not _task.done()
