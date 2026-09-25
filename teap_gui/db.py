"""Engine and session factory. SQLite by default; DATABASE_URL overrides."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session as OrmSession, sessionmaker

from . import migrate, secrets as secret_store

DATA_DIR = Path(os.environ.get("TEAP_GUI_DATA", "./data")).resolve()

_engine = None
_Factory: sessionmaker | None = None


def init() -> None:
    """Create the data directory, encryption key and engine; migrate the schema."""
    global _engine, _Factory
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secret_store.init(DATA_DIR)
    url = os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR / 'teap.db'}")
    _engine = create_engine(url, connect_args={"check_same_thread": False}
                            if url.startswith("sqlite") else {})
    migrate.upgrade(_engine)
    _Factory = sessionmaker(bind=_engine, expire_on_commit=False)


def factory() -> sessionmaker:
    """The raw session factory, for background tasks outliving a request."""
    if _Factory is None:
        raise RuntimeError("teap_gui.db.init() must be called first")
    return _Factory


def get_session() -> Iterator[OrmSession]:
    """FastAPI dependency yielding a database session."""
    if _Factory is None:
        raise RuntimeError("teap_gui.db.init() must be called first")
    db = _Factory()
    try:
        yield db
    finally:
        db.close()
