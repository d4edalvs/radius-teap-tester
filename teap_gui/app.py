"""FastAPI application — Sessions, Generate, Certificates, Wiki, Servers."""

from __future__ import annotations

import asyncio
import datetime as dt
import struct
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from teap_tester import radius
from . import template as tmpl
from teap_tester.state_machine import build_request_attrs
from teap_tester.types import RadiusAttr, TEAPTestConfig
from teap_tester.accounting import AcctSession, send as acct_send
from teap_tester.types import AcctStatusType

from . import certs as certlib, coa_listener, db, expiry, generator, interim, secrets as secret_store
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
    interim.start(db.factory())
    expiry.start(db.factory())


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
                  note: str = "", error: str = "", page_no: int = 1,
                  database: OrmSession = Depends(db.get_session)):
    from sqlalchemy import func
    per_page = 100
    stmt = select(Session).order_by(Session.started.desc())
    count_stmt = select(func.count()).select_from(Session)
    if bulk:
        stmt = stmt.where(Session.bulk == bulk)
        count_stmt = count_stmt.where(Session.bulk == bulk)
    if status:
        stmt = stmt.where(Session.status == status)
        count_stmt = count_stmt.where(Session.status == status)

    total = database.scalar(count_stmt) or 0
    pages = max(1, (total + per_page - 1) // per_page)
    page_no = min(max(1, page_no), pages)
    rows = database.scalars(
        stmt.offset((page_no - 1) * per_page).limit(per_page)).all()
    bulks = database.scalars(select(Session.bulk).distinct()).all()
    return page(request, "sessions.html", "sessions",
                sessions=rows, bulks=bulks, bulk=bulk, status=status,
                note=note, error=error, page_no=page_no, pages=pages, total=total,
                interim_on=interim.running(),
                interim_interval=interim.state(db.factory())[1])


@app.get("/sessions.csv")
def sessions_csv(bulk: str = "", status: str = "",
                 database: OrmSession = Depends(db.get_session)):
    """Export the current filter as CSV."""
    import csv
    import io
    stmt = select(Session).order_by(Session.started.desc())
    if bulk:
        stmt = stmt.where(Session.bulk == bulk)
    if status:
        stmt = stmt.where(Session.status == status)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["started", "bulk", "status", "acct_status", "mac", "ip",
                     "username", "machine_name", "acct_session_id", "class",
                     "duration_s", "reauth_count"])
    for s in database.scalars(stmt).all():
        writer.writerow([
            s.started.isoformat(), s.bulk, s.status, s.acct_status, s.mac, s.ip,
            s.username, s.machine_name, s.acct_session_id,
            bytes.fromhex(s.class_blob).decode("latin1") if s.class_blob else "",
            f"{s.duration:.3f}", s.reauth_count])
    return Response(buf.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": 'attachment; filename="sessions.csv"'})


@app.post("/sessions/delete")
def sessions_delete(session_ids: list[str] = Form(default=[]),
                    database: OrmSession = Depends(db.get_session)):
    from urllib.parse import quote
    removed = 0
    for sid in session_ids:
        row = database.get(Session, sid)
        if row is not None:
            database.delete(row)
            removed += 1
    database.commit()
    return RedirectResponse(f"/sessions?note={quote(f'deleted {removed}')}",
                            status_code=303)


@app.post("/servers/{server_id}/edit")
def server_edit(server_id: str, name: str = Form(...), address: str = Form(...),
                auth_port: int = Form(1812), acct_port: int = Form(1813),
                secret: str = Form(""), coa_enabled: bool = Form(False),
                database: OrmSession = Depends(db.get_session)):
    row = database.get(Server, server_id)
    if row is not None:
        row.name, row.address = name, address
        row.auth_port, row.acct_port = auth_port, acct_port
        row.coa_enabled = coa_enabled
        row.ad_hoc = False
        if secret:                       # blank leaves the stored secret alone
            row.secret_enc = secret_store.encrypt(secret)
        database.commit()
    return RedirectResponse("/servers", status_code=303)


@app.post("/sessions/interim")
async def sessions_interim_timer(enabled: bool = Form(False),
                           interval: int = Form(interim.DEFAULT_INTERVAL),
                           database: OrmSession = Depends(db.get_session)):
    """Turn the periodic Interim-Update timer on or off."""
    from urllib.parse import quote
    interval = max(60, min(interval, 86400))
    interim.set_setting(database, interim.KEY_INTERVAL, str(interval))
    interim.set_setting(database, interim.KEY_ENABLED, "1" if enabled else "0")
    if enabled:
        interim.start(db.factory())
        note = f"interim updates every {interval}s"
    else:
        interim.stop()
        note = "interim updates stopped"
    return RedirectResponse(f"/sessions?note={quote(note)}", status_code=303)


@app.post("/certificates/{cert_id}/rename")
def certificate_rename(cert_id: str, friendly_name: str = Form(...),
                       type: str = Form(...),
                       database: OrmSession = Depends(db.get_session)):
    """Rename or re-file a certificate.

    Everything else about a certificate comes from the file itself and cannot
    be edited; replacing the content means uploading again.
    """
    row = database.get(Certificate, cert_id)
    tab = row.type if row else "trusted"
    if row is not None and type in CERT_TYPES:
        if type != "trusted" and not row.key_pem_enc:
            return RedirectResponse(
                f"/certificates?tab={tab}&error=an+identity+certificate+needs+a+private+key",
                status_code=303)
        row.friendly_name = friendly_name
        row.type = type
        tab = type
        database.commit()
    return RedirectResponse(f"/certificates?tab={tab}", status_code=303)


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
        concurrency: int = Form(1), auto_accounting: bool = Form(False),
        session_lifetime: int = Form(0), termination_action: int = Form(0),
        server_mode: str = Form("saved"), server_id: str = Form(""),
        srv_name: str = Form(""), srv_address: str = Form(""),
        srv_auth_port: int = Form(1812), srv_acct_port: int = Form(1813),
        srv_secret: str = Form(""), srv_save: bool = Form(False),
        identity_mode: str = Form("from_cert"),
        identity: str = Form(""), machine_identity: str = Form(""),
        user_method: str = Form("eap_tls"), machine_method: str = Form("none"),
        user_cert_id: str = Form(""), machine_cert_id: str = Form(""),
        user_username: str = Form(""), user_password: str = Form(""),
        machine_username: str = Form(""), machine_password: str = Form(""),
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
        if server_mode == "inline":
            if not srv_address or not srv_secret:
                raise ValueError("an inline server needs an address and a shared secret")
            # Accounting and CoA resolve the secret through the server row, so
            # one is created even when the user does not want it kept.
            inline = Server(name=srv_name or f"{srv_address} (ad-hoc)",
                            address=srv_address, auth_port=srv_auth_port,
                            acct_port=srv_acct_port,
                            secret_enc=secret_store.encrypt(srv_secret),
                            coa_enabled=True, ad_hoc=not srv_save)
            database.add(inline)
            database.commit()
            server_id = inline.id
        elif not server_id:
            raise ValueError("select a server, or enter one directly")
        if count < 1 or count > 10000:
            raise ValueError("amount of sessions must be between 1 and 10000")
        # A leg not in use contributes no credential of any kind.
        if user_method != "eap_tls":
            user_cert_id = ""
        if machine_method != "eap_tls":
            machine_cert_id = ""
        if user_method != "mschapv2":
            user_username = user_password = ""
        if machine_method != "mschapv2":
            machine_username = machine_password = ""

        if user_method == "mschapv2" and not (user_username and user_password):
            raise ValueError("MS-CHAPv2 for the user leg needs a name and password")
        if machine_method == "mschapv2" and not (machine_username and machine_password):
            raise ValueError("MS-CHAPv2 for the machine leg needs a name and password")
        if user_method == "eap_tls" and not user_cert_id:
            raise ValueError("EAP-TLS for the user leg needs a certificate")
        if machine_method == "eap_tls" and not machine_cert_id:
            raise ValueError("EAP-TLS for the machine leg needs a certificate")
        if user_method == "none" and machine_method == "none":
            raise ValueError("at least one leg must be used")

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
        # A password leg names itself: there is no certificate to read from.
        if user_method == "mschapv2":
            identity = user_username
        if machine_method == "mschapv2":
            machine_identity = machine_username
        if not identity and not machine_identity:
            raise ValueError("no identity was given or could be derived")
        outer_identity = "anonymous" if identity_mode == "anonymous" else ""
        macs = generator._values(mac_mode, count, pool=mac_list, cidr="", oui=mac_oui)
        ips = []
        if ip_mode == "list" or ip_cidr:
            ips = generator._values(ip_mode, count, pool=ip_list,
                                    cidr=ip_cidr or "0.0.0.0/32", oui="")
        # Keep the raw text: values may be templates that must be rendered
        # once per session. Validate now against a sample so mistakes surface
        # here rather than on every session.
        attr_lines = [ln.strip() for ln in radius_attrs.splitlines() if ln.strip()]
        for line in attr_lines:
            radius.parse_attribute_spec(
                tmpl.render(line, mac="00-11-22-33-44-55", ip="10.0.0.1",
                            session="TEST", index=0, ssid=""))
        tmpl.render(called_station_id, mac="00-11-22-33-44-55", ip="10.0.0.1",
                    session="TEST", index=0, ssid="")
    except (ValueError, tmpl.TemplateError) as exc:
        return RedirectResponse(f"/generate?error={quote(str(exc))}", status_code=303)

    job = Job(name=job_name, bulk=bulk or "none", server_id=server_id, total=count,
              params_json={
                  "identity": identity, "machine_identity": machine_identity,
                  "outer_identity": outer_identity, "identity_mode": identity_mode,
                  "user_cert_id": user_cert_id or None,
                  "machine_cert_id": machine_cert_id or None,
                  "user_method": user_method, "machine_method": machine_method,
                  # Encrypted, like a shared secret: job parameters are stored
                  # in the clear otherwise.
                  "password_enc": secret_store.encrypt(user_password) if user_password else "",
                  "machine_password_enc": (secret_store.encrypt(machine_password)
                                           if machine_password else ""),
                  "ca_cert_id": ca_cert_id or None, "chain_mode": chain_mode,
                  "source_ip": source_ip, "called_station_id": called_station_id,
                  "nas_port_type": nas_port_type, "framed_mtu": framed_mtu,
                  "timeout": timeout, "exchange_timeout": exchange_timeout,
                  "retries": retries, "latency_ms": latency_ms,
                  "concurrency": max(1, min(concurrency, 200)),
                  "auto_accounting": auto_accounting,
                  "session_lifetime": max(0, session_lifetime),
                  "termination_action": termination_action,
                  "macs": macs, "ips": ips, "attr_lines": attr_lines,
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


# ── Compiled attribute preview ──────────────────────────────

# Words that are acronyms in the RFCs and should not be title-cased.
_ACRONYMS = {"Nas": "NAS", "Ip": "IP", "Mtu": "MTU", "Eap": "EAP", "Id": "Id",
             "Acct": "Acct", "Mac": "MAC"}


def attr_name(attr_type: int) -> str:
    """Human name for a RADIUS attribute, derived from the enum we already have."""
    try:
        parts = RadiusAttr(attr_type).name.split("_")
    except ValueError:
        return f"Attribute {attr_type}"
    return "-".join(_ACRONYMS.get(p.title(), p.title()) for p in parts)


def _render_value(attr_type: int, value: bytes) -> str:
    if attr_type in (RadiusAttr.NAS_IP_ADDRESS, RadiusAttr.FRAMED_IP_ADDRESS) \
            and len(value) == 4:
        return ".".join(str(b) for b in value)
    if len(value) == 4 and attr_type in (
            RadiusAttr.NAS_PORT, RadiusAttr.NAS_PORT_TYPE,
            RadiusAttr.SERVICE_TYPE, RadiusAttr.FRAMED_MTU):
        return str(struct.unpack("!I", value)[0])
    if attr_type == RadiusAttr.EAP_MESSAGE:
        return f"<EAP payload, {len(value)} octets>"
    try:
        text = value.decode()
        if text.isprintable():
            return text
    except UnicodeDecodeError:
        pass
    return "0x" + value.hex()


@app.post("/generate/preview", response_class=HTMLResponse)
def generate_preview(request: Request,
                     source_ip: str = Form(""), called_station_id: str = Form(""),
                     nas_port_type: int = Form(15), framed_mtu: int = Form(1500),
                     nas_identifier: str = Form(""), nas_port: int = Form(1),
                     identity_mode: str = Form("from_cert"),
                     identity: str = Form(""), user_cert_id: str = Form(""),
                     mac_mode: str = Form("random"), mac_oui: str = Form(""),
                     radius_attrs: str = Form(""),
                     database: OrmSession = Depends(db.get_session)):
    """The attributes an Access-Request will actually carry.

    Built with the same function the protocol uses, so the preview cannot
    drift from what goes on the wire.
    """
    shown_identity = identity
    if identity_mode in ("from_cert", "anonymous") and user_cert_id:
        cert = database.get(Certificate, user_cert_id)
        if cert:
            try:
                shown_identity = certlib.identity_from_cert(cert.content_pem, "user")
            except Exception:
                shown_identity = ""
    outer = "anonymous" if identity_mode == "anonymous" else shown_identity

    try:
        extra = [(t, bytes.fromhex(h)) for t, h in _parse_attr_lines(radius_attrs)]
        error = ""
    except ValueError as exc:
        extra, error = [], str(exc)

    cfg = TEAPTestConfig(
        radius_host="", radius_port=1812, radius_secret="",
        identity=shown_identity, outer_identity=outer,
        source_ip=source_ip, called_station_id=called_station_id,
        nas_port_type=nas_port_type, framed_mtu=framed_mtu,
        nas_identifier=nas_identifier, nas_port=nas_port,
        calling_station_id=generator.random_mac(mac_oui) if mac_mode == "random"
                           else "from list",
        extra_attrs=extra)

    attrs = build_request_attrs(cfg, b"\x02\x00\x00\x05\x01",
                                outer_identity=outer,
                                connect_info=("CONNECT 802.11" if nas_port_type == 19
                                              else "CONNECT Ethernet"))
    seen: dict[int, int] = {}
    for t, _ in attrs:
        seen[t] = seen.get(t, 0) + 1
    rows = [(t, attr_name(t), _render_value(t, v), seen[t] > 1) for t, v in attrs]
    dupes = sorted({attr_name(t) for t, c in seen.items() if c > 1})
    return page(request, "_attrs.html", "generate", rows=rows, error=error,
                dupes=dupes)


@app.post("/jobs/delete")
def jobs_delete(job_ids: list[str] = Form(default=[]),
                stop_accounting: bool = Form(False),
                database: OrmSession = Depends(db.get_session)):
    """Delete jobs and the sessions they created.

    A job still running is refused rather than deleted from under its own
    tasks: cancel it first.
    """
    from urllib.parse import quote
    removed = busy = 0
    for job_id in job_ids:
        job = database.get(Job, job_id)
        if job is None:
            continue
        if job.status in ("queued", "running", "cancelling"):
            busy += 1
            continue
        database.delete(job)          # cascades to its sessions
        removed += 1
    database.commit()

    note = f"deleted {removed} job(s)"
    if busy:
        note += f"; {busy} still running — cancel first"
    return RedirectResponse(f"/jobs?note={quote(note)}", status_code=303)


@app.get("/jobs", response_class=HTMLResponse)
def jobs_list(request: Request, note: str = "",
              database: OrmSession = Depends(db.get_session)):
    from sqlalchemy import func
    jobs = database.scalars(select(Job).order_by(Job.started.desc()).limit(200)).all()
    servers = {s.id: s for s in database.scalars(select(Server)).all()}
    # Sessions still accounting-started are live as far as the server is
    # concerned; deleting them locally leaves the server believing otherwise.
    live = dict(database.execute(
        select(Session.job_id, func.count())
        .where(Session.acct_status.in_(("started", "reauthenticated")))
        .group_by(Session.job_id)).all())
    return page(request, "jobs.html", "generate", jobs=jobs, servers=servers,
                live=live, note=note)


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


@app.post("/sessions/reauth")
async def sessions_reauth(session_ids: list[str] = Form(default=[]),
                          database: OrmSession = Depends(db.get_session)):
    """Re-run authentication for the selected sessions."""
    from urllib.parse import quote
    if not session_ids:
        return RedirectResponse("/sessions?error=select+at+least+one+session",
                                status_code=303)
    # Concurrent, like generation: 50 sessions sequentially would be minutes.
    limit = asyncio.Semaphore(5)

    async def one(sid: str) -> bool:
        async with limit:
            return await generator.reauth_session(sid, db.factory())

    results = await asyncio.gather(*(one(sid) for sid in session_ids),
                                   return_exceptions=True)
    ok = sum(1 for r in results if r is True)
    note = f"reauth: {ok} of {len(session_ids)} re-authenticated"
    return RedirectResponse(f"/sessions?note={quote(note)}", status_code=303)


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
            if action == "stop":
                # Stop the lifetime clock too, or the expiry timer would later
                # fire on a session that has already ended.
                row.expires_at = None
            elif action == "start" and row.lifetime_seconds:
                row.expires_at = (dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
                                  + dt.timedelta(seconds=row.lifetime_seconds))
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
    raw = path.read_text() if path.exists() else "# Not found"
    warning = ""
    try:
        import markdown as md
        body = md.markdown(raw, extensions=["tables", "fenced_code", "toc",
                                            "sane_lists", "attr_list"])
    except ImportError:
        # A missing optional dependency should not take the page down.
        from html import escape
        body = f"<pre>{escape(raw)}</pre>"
        warning = ("Markdown is not installed, so this page is shown as plain "
                   "text. Run: pip install -e '.[gui]'")
    pages = sorted(p.stem for p in (HERE.parent / "docs" / "wiki").glob("*.md")) \
        if (HERE.parent / "docs" / "wiki").exists() else []
    return page(request, "wiki.html", "wiki",
                body=body, pages=pages, page_name=page_name,
                warning=warning)
