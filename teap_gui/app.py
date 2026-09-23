"""FastAPI application — Sessions, Generate, Certificates, Wiki, Servers."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from teap_tester import radius
from teap_tester.accounting import AcctSession, send as acct_send
from teap_tester.types import AcctStatusType

from . import certs as certlib, coa_listener, db, generator, secrets as secret_store
from .models import Certificate, Job, Server, Session

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))

app = FastAPI(title="TEAP Tester")

# Background jobs need a strong reference or the loop may collect them
# mid-run; asyncio only holds a weak one.
_running: set = set()
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


_coa_transport = None


@app.on_event("startup")
async def _startup() -> None:
    global _coa_transport
    db.init()
    import os
    port = int(os.environ.get("TEAP_GUI_COA_PORT", coa_listener.DEFAULT_PORT))
    _coa_transport = await coa_listener.start(db.factory(), port)


@app.on_event("shutdown")
async def _shutdown() -> None:
    if _coa_transport is not None:
        _coa_transport.close()


def page(request: Request, name: str, active: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name=name, context={"active": active, **ctx})


@app.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse("/generate", status_code=303)


# ── Sessions ────────────────────────────────────────────────

@app.get("/sessions", response_class=HTMLResponse)
def sessions_list(request: Request, bulk: str = "", status: str = "",
                  note: str = "", error: str = "",
                  database: OrmSession = Depends(db.get_session)):
    stmt = select(Session).order_by(Session.started.desc()).limit(500)
    if bulk:
        stmt = stmt.where(Session.bulk == bulk)
    if status:
        stmt = stmt.where(Session.status == status)
    rows = database.scalars(stmt).all()
    bulks = database.scalars(select(Session.bulk).distinct()).all()
    return page(request, "sessions.html", "sessions",
                sessions=rows, bulks=bulks, bulk=bulk, status=status,
                note=note, error=error)


@app.get("/sessions/{session_id}", response_class=HTMLResponse)
def session_detail(request: Request, session_id: str,
                   database: OrmSession = Depends(db.get_session)):
    row = database.get(Session, session_id)
    return page(request, "session_detail.html", "sessions", session=row)


# ── Servers ─────────────────────────────────────────────────

@app.get("/servers", response_class=HTMLResponse)
def servers_list(request: Request, database: OrmSession = Depends(db.get_session)):
    rows = database.scalars(select(Server).order_by(Server.name)).all()
    return page(request, "servers.html", "servers", servers=rows)


@app.post("/servers")
def server_create(name: str = Form(...), address: str = Form(...),
                  auth_port: int = Form(1812), acct_port: int = Form(1813),
                  secret: str = Form(...), coa_enabled: bool = Form(False),
                  database: OrmSession = Depends(db.get_session)):
    database.add(Server(name=name, address=address,
                        auth_port=auth_port, acct_port=acct_port,
                        secret_enc=secret_store.encrypt(secret),
                        coa_enabled=coa_enabled))
    database.commit()
    return RedirectResponse("/servers", status_code=303)


@app.post("/servers/{server_id}/delete")
def server_delete(server_id: str, database: OrmSession = Depends(db.get_session)):
    row = database.get(Server, server_id)
    if row:
        database.delete(row)
        database.commit()
    return RedirectResponse("/servers", status_code=303)


# ── Generate ────────────────────────────────────────────────

@app.get("/generate", response_class=HTMLResponse)
def generate_form(request: Request, error: str = "",
                  database: OrmSession = Depends(db.get_session)):
    servers = database.scalars(select(Server).order_by(Server.name)).all()
    certs = database.scalars(select(Certificate).order_by(Certificate.friendly_name)).all()
    return page(request, "generate.html", "generate", error=error,
                servers=servers,
                trusted=[c for c in certs if c.type == "trusted"],
                user_certs=[c for c in certs if c.type == "identity_user"],
                machine_certs=[c for c in certs if c.type == "identity_machine"])


def _parse_attr_lines(text: str) -> list:
    """One TYPE=VALUE per line, using the same parser as the CLI.

    Returned as [type, hex] pairs because the job parameters are a JSON
    column; the runner converts back to bytes.
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            t, data = radius.parse_attribute_spec(line)
            out.append([t, data.hex()])
    return out


@app.post("/generate")
async def generate_run(
        job_name: str = Form("job"), count: int = Form(1),
        latency_ms: int = Form(0), bulk: str = Form("none"),
        concurrency: int = Form(1),
        server_id: str = Form(...),
        identity_mode: str = Form("from_cert"),
        identity: str = Form(""), machine_identity: str = Form(""),
        user_cert_id: str = Form(""), machine_cert_id: str = Form(""),
        ca_cert_id: str = Form(""), chain_mode: str = Form("full"),
        source_ip: str = Form(""), called_station_id: str = Form(""),
        nas_port_type: int = Form(15), framed_mtu: int = Form(1500),
        timeout: float = Form(30.0), exchange_timeout: float = Form(10.0),
        retries: int = Form(3),
        mac_mode: str = Form("random"), mac_oui: str = Form(""), mac_list: str = Form(""),
        ip_mode: str = Form("random"), ip_cidr: str = Form(""), ip_list: str = Form(""),
        radius_attrs: str = Form(""),
        database: OrmSession = Depends(db.get_session)):
    from urllib.parse import quote
    try:
        if count < 1 or count > 10000:
            raise ValueError("amount of sessions must be between 1 and 10000")
        if not user_cert_id and not machine_cert_id:
            raise ValueError("select a user or a machine identity certificate")
        if identity_mode in ("from_cert", "anonymous"):
            # Derive from the certificates so there is nothing to mistype.
            if user_cert_id:
                c = database.get(Certificate, user_cert_id)
                identity = certlib.identity_from_cert(c.content_pem, "user")
            if machine_cert_id:
                c = database.get(Certificate, machine_cert_id)
                machine_identity = certlib.identity_from_cert(c.content_pem, "machine")
            if user_cert_id and not identity:
                raise ValueError("could not derive an identity from the user "
                                 "certificate — no UPN, SAN email or CN")
            if machine_cert_id and not machine_identity:
                raise ValueError("could not derive a machine identity from the "
                                 "machine certificate — no SAN DNS or CN")
        else:
            if user_cert_id and not identity:
                raise ValueError("a user certificate needs an identity")
            if machine_cert_id and not machine_identity:
                raise ValueError("a machine certificate needs a machine identity")
        outer_identity = "anonymous" if identity_mode == "anonymous" else ""
        macs = generator._values(mac_mode, count, pool=mac_list, cidr="", oui=mac_oui)
        ips = []
        if ip_mode == "list" or ip_cidr:
            ips = generator._values(ip_mode, count, pool=ip_list,
                                    cidr=ip_cidr or "0.0.0.0/32", oui="")
        extra = _parse_attr_lines(radius_attrs)
    except ValueError as exc:
        return RedirectResponse(f"/generate?error={quote(str(exc))}", status_code=303)

    job = Job(name=job_name, bulk=bulk or "none", server_id=server_id, total=count,
              params_json={
                  "identity": identity, "machine_identity": machine_identity,
                  "outer_identity": outer_identity, "identity_mode": identity_mode,
                  "user_cert_id": user_cert_id or None,
                  "machine_cert_id": machine_cert_id or None,
                  "ca_cert_id": ca_cert_id or None, "chain_mode": chain_mode,
                  "source_ip": source_ip, "called_station_id": called_station_id,
                  "nas_port_type": nas_port_type, "framed_mtu": framed_mtu,
                  "timeout": timeout, "exchange_timeout": exchange_timeout,
                  "retries": retries, "latency_ms": latency_ms,
                  "concurrency": max(1, min(concurrency, 200)),
                  "macs": macs, "ips": ips, "extra_attrs": extra,
              })
    database.add(job)
    database.commit()
    task = asyncio.create_task(generator.run_job(job.id, db.factory()))
    task._teap_job_id = job.id
    _running.add(task)
    task.add_done_callback(_running.discard)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@app.post("/jobs/{job_id}/cancel")
def job_cancel(job_id: str, database: OrmSession = Depends(db.get_session)):
    job = database.get(Job, job_id)
    if job and job.status in ("queued", "running"):
        job.status = "cancelling"
        database.commit()
        for task in list(_running):
            if getattr(task, "_teap_job_id", None) == job_id:
                task.cancel()
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: str,
               database: OrmSession = Depends(db.get_session)):
    job = database.get(Job, job_id)
    return page(request, "job.html", "generate", job=job)


@app.get("/jobs/{job_id}/progress", response_class=HTMLResponse)
def job_progress(request: Request, job_id: str,
                 database: OrmSession = Depends(db.get_session)):
    database.expire_all()
    job = database.get(Job, job_id)
    return page(request, "_progress.html", "generate", job=job)


# ── Certificates ────────────────────────────────────────────

CERT_TYPES = {
    "trusted": "Trusted Certificates",
    "identity_user": "Identity — User",
    "identity_machine": "Identity — Machine",
}


@app.get("/certificates", response_class=HTMLResponse)
def certificates_list(request: Request, tab: str = "trusted", error: str = "",
                      database: OrmSession = Depends(db.get_session)):
    rows = database.scalars(
        select(Certificate).order_by(Certificate.friendly_name)).all()
    grouped = {k: [c for c in rows if c.type == k] for k in CERT_TYPES}
    states = {c.id: certlib.expiry_state(c.valid_to) for c in rows}
    return page(request, "certificates.html", "certificates",
                grouped=grouped, types=CERT_TYPES, states=states,
                tab=tab if tab in CERT_TYPES else "trusted", error=error)


@app.post("/certificates")
async def certificate_upload(
        friendly_name: str = Form(...), type: str = Form(...),
        passphrase: str = Form(""),
        cert_file: UploadFile = File(...),
        key_file: UploadFile | None = File(None),
        database: OrmSession = Depends(db.get_session)):
    if type not in CERT_TYPES:
        return RedirectResponse("/certificates?error=unknown+type", status_code=303)

    blob = await cert_file.read()
    key_pem = ""
    try:
        if cert_file.filename.lower().endswith((".p12", ".pfx")):
            leaf, key_pem, chain = certlib.load_pkcs12(blob, passphrase)
            content = "\n".join([leaf] + chain)
        else:
            content = blob.decode()
            if key_file is not None and key_file.filename:
                key_pem = (await key_file.read()).decode()
        if not certlib.split_pem_chain(content):
            raise ValueError("no PEM certificate found in the uploaded file")
        meta = certlib.describe(certlib.split_pem_chain(content)[0])
        if key_pem and not certlib.key_matches_cert(
                certlib.split_pem_chain(content)[0], key_pem):
            raise ValueError("private key does not match the certificate")
        if type != "trusted" and not key_pem:
            raise ValueError("an identity certificate needs its private key")
    except Exception as exc:  # surfaced to the user rather than a 500
        from urllib.parse import quote
        return RedirectResponse(
            f"/certificates?tab={type}&error={quote(str(exc))}", status_code=303)

    database.add(Certificate(
        friendly_name=friendly_name, type=type, content_pem=content,
        key_pem_enc=secret_store.encrypt(key_pem) if key_pem else None,
        **meta))
    database.commit()
    return RedirectResponse(f"/certificates?tab={type}", status_code=303)


@app.post("/certificates/{cert_id}/delete")
def certificate_delete(cert_id: str, database: OrmSession = Depends(db.get_session)):
    row = database.get(Certificate, cert_id)
    tab = row.type if row else "trusted"
    if row:
        database.delete(row)
        database.commit()
    return RedirectResponse(f"/certificates?tab={tab}", status_code=303)


# ── Accounting ──────────────────────────────────────────────

ACCT_ACTIONS = {
    "start": AcctStatusType.START,
    "interim": AcctStatusType.INTERIM_UPDATE,
    "stop": AcctStatusType.STOP,
}


@app.post("/sessions/accounting")
async def sessions_accounting(
        action: str = Form(...),
        session_ids: list[str] = Form(default=[]),
        database: OrmSession = Depends(db.get_session)):
    """Send an accounting record for each selected session."""
    from urllib.parse import quote
    status = ACCT_ACTIONS.get(action)
    if status is None:
        return RedirectResponse("/sessions?error=unknown+action", status_code=303)
    if not session_ids:
        return RedirectResponse("/sessions?error=select+at+least+one+session",
                                status_code=303)

    ok = failed = 0
    last_error = ""
    for sid in session_ids:
        row = database.get(Session, sid)
        if row is None:
            continue
        server = database.get(Server, row.server_id)
        if server is None:
            failed += 1
            last_error = "server for this session no longer exists"
            continue
        acct = AcctSession(
            acct_session_id=row.acct_session_id,
            username=row.username or row.mac,
            nas_ip=row.request_attrs_json.get("source_ip", "") or "0.0.0.0",
            calling_station_id=row.mac,
            framed_ip=row.ip,
            class_blob=bytes.fromhex(row.class_blob) if row.class_blob else b"",
        )
        elapsed = row.acct_session_time + 60 if status != AcctStatusType.START else 0
        result = await acct_send(
            server.address, server.acct_port,
            secret_store.decrypt(server.secret_enc), acct, status,
            session_time=elapsed,
            input_octets=elapsed * 128, output_octets=elapsed * 256,
        ) if status != AcctStatusType.START else await acct_send(
            server.address, server.acct_port,
            secret_store.decrypt(server.secret_enc), acct, status)

        if result.success:
            ok += 1
            row.acct_status = {"start": "started", "interim": "started",
                               "stop": "stopped"}[action]
            row.acct_session_time = elapsed
        else:
            failed += 1
            last_error = result.message
        database.commit()

    note = f"{action}: {ok} ok"
    if failed:
        note += f", {failed} failed — {last_error}"
    return RedirectResponse(f"/sessions?note={quote(note)}", status_code=303)


# ── Wiki ────────────────────────────────────────────────────

@app.get("/wiki", response_class=HTMLResponse)
def wiki(request: Request, page_name: str = "index"):
    path = HERE.parent / "docs" / "wiki" / f"{page_name}.md"
    body = path.read_text() if path.exists() else "# Not found"
    pages = sorted(p.stem for p in (HERE.parent / "docs" / "wiki").glob("*.md")) \
        if (HERE.parent / "docs" / "wiki").exists() else []
    return page(request, "wiki.html", "wiki",
                body=body, pages=pages, page_name=page_name)
