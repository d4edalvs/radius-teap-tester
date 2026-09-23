"""Session generation: MAC/IP strategies, chain trimming, and the job runner."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import random
import secrets as pysecrets

from sqlalchemy.orm import Session as OrmSession

from teap_tester import run_teap_test

from . import certs as certlib, secrets as secret_store
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


async def _run_one(database, job_id, server, secret, certs, p, index) -> None:
    mac = p["macs"][index]
    ip = p["ips"][index] if p.get("ips") else ""
    sid = acct_session_id()
    user_pem, user_key = certs["user"] or ("", "")
    mach_pem, mach_key = certs["machine"] or ("", "")

    result = await run_teap_test(
        radius_host=server.address, radius_port=server.auth_port,
        radius_secret=secret,
        identity=p.get("identity", ""), machine_identity=p.get("machine_identity", ""),
        outer_identity=p.get("outer_identity", ""),
        client_cert_pem=user_pem, client_key_pem=user_key,
        machine_cert_pem=mach_pem, machine_key_pem=mach_key,
        ca_chain_pem=certs["ca"],
        source_ip=p.get("source_ip", ""),
        calling_station_id=mac,
        called_station_id=p.get("called_station_id", ""),
        nas_port_type=p.get("nas_port_type", 15),
        framed_mtu=p.get("framed_mtu", 1500),
        timeout=p.get("timeout", 30.0),
        exchange_timeout=p.get("exchange_timeout", 10.0),
        retries=p.get("retries", 3),
        extra_attrs=[(t, bytes.fromhex(h)) for t, h in p.get("extra_attrs", [])],
    )

    attrs = result.reply_attrs
    job = database.get(Job, job_id)
    database.add(Session(
        job_id=job.id, bulk=job.bulk, server_id=server.id,
        mac=mac, ip=ip,
        username=p.get("identity", ""), machine_name=p.get("machine_identity", ""),
        acct_session_id=sid,
        class_blob=attrs.get(ATTR_CLASS, ""),
        state_blob=attrs.get(ATTR_STATE, ""),
        status="accepted" if result.success else "rejected",
        duration=result.duration,
        reply_attrs_json=attrs,
        request_attrs_json={"calling_station_id": mac, "framed_ip": ip},
        log_json=[{"time": e.timestamp, "direction": e.direction,
                   "layer": e.layer, "message": e.message}
                  for e in result.log_entries],
    ))
    if result.success:
        job.completed += 1
    else:
        job.failed += 1
    database.commit()
