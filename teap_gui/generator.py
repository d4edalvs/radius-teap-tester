"""Session generation: MAC/IP strategies, chain trimming, and the job runner."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import random
import secrets as pysecrets

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from teap_tester import run_teap_test
from teap_tester.accounting import AcctSession, send as acct_send
from teap_tester.types import AcctStatusType

from teap_tester import radius

from . import certs as certlib, expiry, secrets as secret_store, template as tmpl
from .models import Certificate, Job, Server, Session

# RADIUS attribute numbers worth naming in the session record
ATTR_CLASS = 25
ATTR_STATE = 24
ATTR_FRAMED_IP = 8


def random_mac(oui: str = "") -> str:
    """AA-BB-CC-DD-EE-FF form, per RFC 3580 for Calling-Station-Id."""
    if oui:
        head = [int(x, 16) for x in oui.replace(":", "-").split("-")[:3]]
    else:
        head = [0x02, random.randrange(256), random.randrange(256)]
    tail = [random.randrange(256) for _ in range(6 - len(head))]
    return "-".join(f"{b:02X}" for b in head + tail)


def random_ip(cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses <= 2:
        return str(net.network_address)
    return str(net.network_address + random.randrange(1, net.num_addresses - 1))


def _values(mode: str, count: int, *, pool: str, cidr: str, oui: str) -> list[str]:
    """Produce `count` MACs or IPs from either a pasted list or a generator."""
    if mode == "list":
        items = [line.strip() for line in pool.splitlines() if line.strip()]
        if not items:
            raise ValueError("list mode selected but no values were supplied")
        return [items[i % len(items)] for i in range(count)]
    if cidr:
        return [random_ip(cidr) for _ in range(count)]
    return [random_mac(oui) for _ in range(count)]


def trim_chain(pem: str, mode: str) -> str:
    """Apply the 'what certificates should be sent' choice.

    full      — leaf plus every certificate stored with it
    no_root   — same, minus any self-signed certificate
    leaf      — identity certificate only
    """
    blocks = certlib.split_pem_chain(pem)
    if not blocks:
        return pem
    if mode == "leaf":
        return blocks[0]
    if mode == "no_root":
        kept = [blocks[0]]
        for b in blocks[1:]:
            if not certlib.describe(b)["self_signed"]:
                kept.append(b)
        return "\n".join(kept)
    return "\n".join(blocks)


def acct_session_id() -> str:
    return pysecrets.token_hex(8).upper()


async def run_job(job_id: str, factory) -> None:
    """Execute a job's sessions, persisting each result as it lands.

    Sessions run concurrently up to the job's concurrency setting. Each one
    gets its own database session: a SQLAlchemy Session is not safe to share
    between interleaving coroutines.
    """
    control = factory()
    try:
        job = control.get(Job, job_id)
        if job is None:
            return
        job.status = "running"
        control.commit()

        p = job.params_json
        server = control.get(Server, job.server_id)
        secret = secret_store.decrypt(server.secret_enc)
        certs = _resolve_certs(control, p)
        limit = asyncio.Semaphore(max(1, int(p.get("concurrency", 1))))

        async def one(index: int) -> None:
            if p.get("latency_ms"):
                await asyncio.sleep(index * p["latency_ms"] / 1000)
            async with limit:
                database = factory()
                try:
                    await _run_one(database, job_id, server, secret, certs, p, index)
                finally:
                    database.close()

        await asyncio.gather(*(one(i) for i in range(job.total)),
                             return_exceptions=True)

        control.expire_all()
        job = control.get(Job, job_id)
        job.status = "cancelled" if job.status == "cancelling" else "done"
        job.finished = dt.datetime.now(dt.timezone.utc)
        control.commit()
    except asyncio.CancelledError:
        job = control.get(Job, job_id)
        if job:
            job.status = "cancelled"
            job.finished = dt.datetime.now(dt.timezone.utc)
            control.commit()
        raise
    except Exception as exc:                      # a failed job must not vanish
        job = control.get(Job, job_id)
        if job:
            job.status = "failed"
            job.params_json = {**job.params_json, "error": str(exc)}
            job.finished = dt.datetime.now(dt.timezone.utc)
            control.commit()
    finally:
        control.close()


def _resolve_certs(database: OrmSession, p: dict) -> dict:
    out = {"user": None, "machine": None, "ca": ""}
    if p.get("user_cert_id"):
        c = database.get(Certificate, p["user_cert_id"])
        out["user"] = (trim_chain(c.content_pem, p["chain_mode"]),
                       secret_store.decrypt(c.key_pem_enc))
    if p.get("machine_cert_id"):
        c = database.get(Certificate, p["machine_cert_id"])
        out["machine"] = (trim_chain(c.content_pem, p["chain_mode"]),
                          secret_store.decrypt(c.key_pem_enc))
    if p.get("ca_cert_id"):
        out["ca"] = database.get(Certificate, p["ca_cert_id"]).content_pem
    return out


def _password(p: dict, key: str) -> str:
    """Decrypt a stored leg password, if one was configured."""
    token = p.get(key) or ""
    return secret_store.decrypt(token) if token else ""


def render_for_session(p: dict, *, mac: str, ip: str, session_id: str,
                       index: int) -> dict:
    """Render templated values for one session.

    Called per session rather than per job: a value referencing $MAC$ or
    rand() must vary with the endpoint, not freeze to the first one.
    """
    ctx = dict(mac=mac, ip=ip, session=session_id, index=index,
               ssid=p.get("ssid", ""))
    attrs = []
    for line in p.get("attr_lines", []):
        try:
            attrs.append(radius.parse_attribute_spec(tmpl.render(line, **ctx)))
        except (ValueError, tmpl.TemplateError):
            continue          # validated at submit time
    return {"called_station_id": tmpl.render(p.get("called_station_id", ""), **ctx),
            "extra_attrs": attrs}


async def _run_one(database, job_id, server, secret, certs, p, index) -> None:
    mac = p["macs"][index]
    ip = p["ips"][index] if p.get("ips") else ""
    sid = acct_session_id()
    user_pem, user_key = certs["user"] or ("", "")
    mach_pem, mach_key = certs["machine"] or ("", "")

    rendered = render_for_session(p, mac=mac, ip=ip, session_id=sid, index=index)
    called = rendered["called_station_id"]
    extra_attrs = rendered["extra_attrs"]

    result = await run_teap_test(
        radius_host=server.address, radius_port=server.auth_port,
        radius_secret=secret,
        identity=p.get("identity", ""), machine_identity=p.get("machine_identity", ""),
        outer_identity=p.get("outer_identity", ""),
        password=_password(p, "password_enc"),
        machine_password=_password(p, "machine_password_enc"),
        client_cert_pem=user_pem, client_key_pem=user_key,
        machine_cert_pem=mach_pem, machine_key_pem=mach_key,
        ca_chain_pem=certs["ca"],
        source_ip=p.get("source_ip", ""),
        calling_station_id=mac,
        called_station_id=called,
        nas_port_type=p.get("nas_port_type", 15),
        framed_mtu=p.get("framed_mtu", 1500),
        nas_identifier=p.get("nas_identifier", ""),
        timeout=p.get("timeout", 30.0),
        exchange_timeout=p.get("exchange_timeout", 10.0),
        retries=p.get("retries", 3),
        extra_attrs=extra_attrs,
    )

    attrs = result.reply_attrs
    job = database.get(Job, job_id)
    lifetime, action = expiry.from_reply(attrs, p.get("session_lifetime", 0),
                                         p.get("termination_action", 0))
    expires_at = (dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
                  + dt.timedelta(seconds=lifetime)) if (result.success and lifetime) else None
    database.add(Session(
        expires_at=expires_at, lifetime_seconds=lifetime,
        termination_action=action,
        job_id=job.id, bulk=job.bulk, server_id=server.id,
        mac=mac, ip=ip,
        username=p.get("identity", ""), machine_name=p.get("machine_identity", ""),
        acct_session_id=sid,
        class_blob=expiry.attr(attrs, ATTR_CLASS) or "",
        state_blob=expiry.attr(attrs, ATTR_STATE) or "",
        status="accepted" if result.success else "rejected",
        duration=result.duration,
        reply_attrs_json=attrs,
        legs_json=result.legs,
        # Record what was actually sent: a rendered template is otherwise
        # unverifiable after the fact.
        request_attrs_json={"calling_station_id": mac, "framed_ip": ip,
                            "called_station_id": called,
                            "extra_attrs": [[t, v.decode("latin1")]
                                            for t, v in extra_attrs]},
        log_json=[{"time": e.timestamp, "direction": e.direction,
                   "layer": e.layer, "message": e.message}
                  for e in result.log_entries],
    ))
    if result.success:
        job.completed += 1
    else:
        job.failed += 1
    database.commit()

    if result.success and p.get("auto_accounting"):
        await _start_accounting(database, server, secret, sid, p, mac, ip,
                                expiry.attr(attrs, ATTR_CLASS) or "")


async def _start_accounting(database, server, secret, sid, p, mac, ip,
                            class_hex: str) -> None:
    """Send Accounting-Start for a session that has just authenticated.

    A failure here does not change the authentication result: the session was
    accepted either way, and conflating the two would hide which one broke.
    """
    row = database.scalars(
        select(Session).where(Session.acct_session_id == sid).limit(1)).first()
    if row is None:
        return
    acct = AcctSession(
        acct_session_id=sid, username=p.get("identity", "") or mac,
        nas_ip=p.get("source_ip", "") or "0.0.0.0",
        calling_station_id=mac, called_station_id=p.get("called_station_id", ""),
        framed_ip=ip, nas_port_type=p.get("nas_port_type", 15),
        class_blob=bytes.fromhex(class_hex) if class_hex else b"")
    try:
        result = await acct_send(server.address, server.acct_port, secret, acct,
                                 AcctStatusType.START,
                                 timeout=p.get("exchange_timeout", 10.0),
                                 retries=p.get("retries", 3),
                                 source_ip=p.get("source_ip", ""))
        row.acct_status = "started" if result.success else "start-failed"
    except Exception:
        row.acct_status = "start-failed"
    database.commit()


async def reauth_session(session_id: str, factory) -> bool:
    """Re-run the TEAP exchange for an existing session.

    Used when a CoA-Request asks for re-authentication, and from the Sessions
    page. The original job's parameters and certificates are reused so the
    exchange matches the one that created the session; only the identifiers
    belonging to this endpoint (its MAC and IP) are carried over.

    The server issues a fresh Class on the new Access-Accept, so the row is
    updated in place — otherwise subsequent accounting would echo a Class the
    server has already retired.
    """
    database: OrmSession = factory()
    try:
        session = database.get(Session, session_id)
        if session is None:
            return False
        job = database.get(Job, session.job_id)
        server = database.get(Server, session.server_id)
        if job is None or server is None:
            session.acct_status = "reauth-failed"
            database.commit()
            return False

        p = job.params_json
        certs = _resolve_certs(database, p)
        user_pem, user_key = certs["user"] or ("", "")
        mach_pem, mach_key = certs["machine"] or ("", "")

        # Re-authentication renders templates again with this session's own
        # values, so a re-auth carries a fresh rand() just as a new session does.
        rendered = render_for_session(
            p, mac=session.mac, ip=session.ip,
            session_id=session.acct_session_id, index=session.reauth_count)

        result = await run_teap_test(
            radius_host=server.address, radius_port=server.auth_port,
            radius_secret=secret_store.decrypt(server.secret_enc),
            identity=p.get("identity", ""),
            machine_identity=p.get("machine_identity", ""),
            outer_identity=p.get("outer_identity", ""),
            password=_password(p, "password_enc"),
            machine_password=_password(p, "machine_password_enc"),
            client_cert_pem=user_pem, client_key_pem=user_key,
            machine_cert_pem=mach_pem, machine_key_pem=mach_key,
            ca_chain_pem=certs["ca"],
            source_ip=p.get("source_ip", ""),
            calling_station_id=session.mac,
            called_station_id=rendered["called_station_id"],
            nas_port_type=p.get("nas_port_type", 15),
            framed_mtu=p.get("framed_mtu", 1500),
            nas_identifier=p.get("nas_identifier", ""),
            timeout=p.get("timeout", 30.0),
            exchange_timeout=p.get("exchange_timeout", 10.0),
            retries=p.get("retries", 3),
            extra_attrs=rendered["extra_attrs"],
        )

        attrs = result.reply_attrs
        session.status = "accepted" if result.success else "rejected"
        session.duration = result.duration
        session.reauth_count += 1
        session.acct_status = "reauthenticated" if result.success else "reauth-failed"
        session.class_blob = expiry.attr(attrs, ATTR_CLASS) or ""
        session.state_blob = expiry.attr(attrs, ATTR_STATE) or ""
        session.reply_attrs_json = attrs
        session.legs_json = result.legs
        session.log_json = [{"time": e.timestamp, "direction": e.direction,
                             "layer": e.layer, "message": e.message}
                            for e in result.log_entries]
        session.changed = dt.datetime.now(dt.timezone.utc)
        database.commit()
        return result.success
    finally:
        database.close()
