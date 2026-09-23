"""Engine and session factory. SQLite by default; DATABASE_URL overrides."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session as OrmSession, sessionmaker

from . import secrets as secret_store
from .models import Base

DATA_DIR = Path(os.environ.get("TEAP_GUI_DATA", "./data")).resolve()

_engine = None
_Factory: sessionmaker | None = None


def init() -> None:
    """Create the data directory, encryption key, engine and schema."""
    global _engine, _Factory
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secret_store.init(DATA_DIR)
    url = os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR / 'teap.db'}")
    _engine = create_engine(url, connect_args={"check_same_thread": False}
                            if url.startswith("sqlite") else {})
    Base.metadata.create_all(_engine)
    _add_missing_columns()
    _Factory = sessionmaker(bind=_engine, expire_on_commit=False)


def _add_missing_columns() -> None:
    """Add columns introduced after a database was first created.

    create_all() only creates missing tables, never missing columns, so a
    schema change would otherwise break an existing data directory.
    """
    from sqlalchemy import inspect, text
    inspector = inspect(_engine)
    with _engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in inspector.get_table_names():
                continue
            have = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in have:
                    continue
                ddl = f"ALTER TABLE {table.name} ADD COLUMN {column.name} " \
                      f"{column.type.compile(_engine.dialect)}"
                if column.default is not None and column.default.is_scalar:
                    ddl += f" DEFAULT {column.default.arg!r}"
                conn.execute(text(ddl))


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
