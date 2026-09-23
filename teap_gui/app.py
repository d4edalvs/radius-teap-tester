"""FastAPI application — Sessions, Generate, Certificates, Wiki, Servers."""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import db, secrets as secret_store
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


# ── Wiki ────────────────────────────────────────────────────

@app.get("/wiki", response_class=HTMLResponse)
def wiki(request: Request, page_name: str = "index"):
    path = HERE.parent / "docs" / "wiki" / f"{page_name}.md"
    body = path.read_text() if path.exists() else "# Not found"
    pages = sorted(p.stem for p in (HERE.parent / "docs" / "wiki").glob("*.md")) \
        if (HERE.parent / "docs" / "wiki").exists() else []
    return page(request, "wiki.html", "wiki",
                body=body, pages=pages, page_name=page_name)
