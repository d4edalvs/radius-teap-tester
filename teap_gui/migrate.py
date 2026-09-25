"""Bring the database schema up to date with Alembic."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

MIGRATIONS = Path(__file__).parent / "migrations"


def config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    return cfg


def upgrade(engine: Engine) -> None:
    """Apply every migration the database has not had yet.

    A database from before migrations existed carries no version, so it runs
    from the baseline too; the baseline only fills in what is missing, so this
    upgrades it in place.
    """
    cfg = config()
    with engine.begin() as connection:
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
