"""Actions applied to many sessions at once.

Sessions paginate, so acting only on ticked checkboxes cannot reach a run
larger than one page. These resolve the target set server-side from the same
filter the page is showing.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from teap_tester.accounting import AcctSession, send as acct_send
from teap_tester.types import AcctStatusType

from . import secrets as secret_store
from .models import BulkOperation, Server, Session

log = logging.getLogger("teap_gui.bulk")

# Accounting is a single short exchange; re-authentication is a full TEAP run.
ACCT_CONCURRENCY = 10
REAUTH_CONCURRENCY = 5

ACTIONS = {
    "start": AcctStatusType.START,
    "interim": AcctStatusType.INTERIM_UPDATE,
    "stop": AcctStatusType.STOP,
}


def resolve(database: OrmSession, scope: str, session_ids: list[str],
            bulk: str = "", status: str = "") -> list[str]:
    """The sessions an action applies to.

    'selected' uses the ticked rows; anything else means the whole current
    filter, including rows on pages the user never opened.
    """
    if scope == "selected":
        return [sid for sid in session_ids if sid]
    stmt = select(Session.id)
    if bulk:
        stmt = stmt.where(Session.bulk == bulk)
    if status:
        stmt = stmt.where(Session.status == status)
    return list(database.scalars(stmt).all())


def _acct_session(row: Session) -> AcctSession:
    return AcctSession(
        acct_session_id=row.acct_session_id,
        username=row.username or row.mac,
        nas_ip=(row.request_attrs_json or {}).get("source_ip", "") or "0.0.0.0",
        calling_station_id=row.mac,
        called_station_id=(row.request_attrs_json or {}).get("called_station_id", ""),
        framed_ip=row.ip,
        class_blob=bytes.fromhex(row.class_blob) if row.class_blob else b"")


async def accounting(factory, session_ids: list[str], action: str) -> tuple[int, int, str]:
    """Send one accounting record per session, concurrently.

    Returns (ok, failed, last error). Concurrent because a few hundred
    sequential exchanges would keep a request open for minutes.
    """
    status = ACTIONS[action]
    limit = asyncio.Semaphore(ACCT_CONCURRENCY)
    errors: list[str] = []

    async def one(sid: str) -> bool:
        async with limit:
            database = factory()
            try:
                row = database.get(Session, sid)
                if row is None:
                    return False
                server = database.get(Server, row.server_id)
                if server is None:
                    errors.append("server for this session no longer exists")
                    return False
                elapsed = (row.acct_session_time + 60
                           if status != AcctStatusType.START else 0)
                kwargs = {} if status == AcctStatusType.START else dict(
                    session_time=elapsed, input_octets=elapsed * 128,
                    output_octets=elapsed * 256)
                result = await acct_send(
                    server.address, server.acct_port,
                    secret_store.decrypt(server.secret_enc),
                    _acct_session(row), status, **kwargs)
                if not result.success:
                    errors.append(result.message)
                    return False
                row.acct_status = {"start": "started", "interim": "started",
                                   "stop": "stopped"}[action]
                row.acct_session_time = elapsed
                if action == "stop":
                    row.expires_at = None
                elif action == "start" and row.lifetime_seconds:
                    row.expires_at = (dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
                                      + dt.timedelta(seconds=row.lifetime_seconds))
                database.commit()
                return True
            except Exception as exc:
                errors.append(str(exc))
                return False
            finally:
                database.close()

    results = await asyncio.gather(*(one(s) for s in session_ids),
                                   return_exceptions=True)
    ok = sum(1 for r in results if r is True)
    return ok, len(session_ids) - ok, errors[-1] if errors else ""


async def run_in_background(factory, operation_id: str, kind: str,
                            session_ids: list[str]) -> None:
    """Long-running bulk work, tracked so the page can show progress."""
    from . import generator

    control = factory()
    try:
        limit = asyncio.Semaphore(REAUTH_CONCURRENCY)

        async def one(sid: str) -> bool:
            async with limit:
                try:
                    return await generator.reauth_session(sid, factory)
                except Exception:
                    log.exception("bulk %s failed for %s", kind, sid)
                    return False

        for coro in asyncio.as_completed([one(s) for s in session_ids]):
            ok = await coro
            operation = control.get(BulkOperation, operation_id)
            if operation is None:
                return
            if ok:
                operation.done += 1
            else:
                operation.failed += 1
            control.commit()

        operation = control.get(BulkOperation, operation_id)
        operation.status = "done"
        operation.finished = dt.datetime.now(dt.timezone.utc)
        control.commit()
    except asyncio.CancelledError:                # the app is shutting down
        operation = control.get(BulkOperation, operation_id)
        if operation:
            operation.status = "interrupted"
            operation.finished = dt.datetime.now(dt.timezone.utc)
            control.commit()
        raise
    except Exception as exc:
        operation = control.get(BulkOperation, operation_id)
        if operation:
            operation.status = "failed"
            operation.note = str(exc)
            operation.finished = dt.datetime.now(dt.timezone.utc)
            control.commit()
    finally:
        control.close()
