"""FastAPI application — Sessions, Generate, Certificates, Wiki, Servers."""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import certs as certlib, db, secrets as secret_store
from .models import Certificate, Job, Server, Session

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))

app = FastAPI(title="TEAP Tester")
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


@app.on_event("startup")
def _startup() -> None:
    db.init()


def page(request: Request, name: str, active: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name=name, context={"active": active, **ctx})


@app.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse("/sessions", status_code=303)


# ── Sessions ────────────────────────────────────────────────

@app.get("/sessions", response_class=HTMLResponse)
def sessions_list(request: Request, bulk: str = "", status: str = "",
                  database: OrmSession = Depends(db.get_session)):
    stmt = select(Session).order_by(Session.started.desc()).limit(500)
    if bulk:
        stmt = stmt.where(Session.bulk == bulk)
    if status:
        stmt = stmt.where(Session.status == status)
    rows = database.scalars(stmt).all()
    bulks = database.scalars(select(Session.bulk).distinct()).all()
    return page(request, "sessions.html", "sessions",
                sessions=rows, bulks=bulks, bulk=bulk, status=status)


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


# ── Wiki ────────────────────────────────────────────────────

@app.get("/wiki", response_class=HTMLResponse)
def wiki(request: Request, page_name: str = "index"):
    path = HERE.parent / "docs" / "wiki" / f"{page_name}.md"
    body = path.read_text() if path.exists() else "# Not found"
    pages = sorted(p.stem for p in (HERE.parent / "docs" / "wiki").glob("*.md")) \
        if (HERE.parent / "docs" / "wiki").exists() else []
    return page(request, "wiki.html", "wiki",
                body=body, pages=pages, page_name=page_name)
