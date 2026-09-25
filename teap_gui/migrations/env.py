"""Alembic environment.

The app runs migrations itself at startup (teap_gui.migrate), passing its own
connection. Run from the command line instead, it connects the way the app
would: DATABASE_URL, else SQLite in TEAP_GUI_DATA.
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine

from teap_gui.models import Base

target_metadata = Base.metadata


def _url() -> str:
    data = Path(os.environ.get("TEAP_GUI_DATA", "./data")).resolve()
    return os.environ.get("DATABASE_URL", f"sqlite:///{data / 'teap.db'}")


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite cannot ALTER most things in place; batch mode rebuilds the
        # table instead, so the same migration runs on SQLite and elsewhere.
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = context.config.attributes.get("connection")
if connection is not None:
    _run(connection)
else:
    with create_engine(_url()).connect() as conn:
        _run(conn)
