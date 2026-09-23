"""SQLAlchemy models."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class AppSetting(Base):
    """Small key/value store so settings survive a restart."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120))
    address: Mapped[str] = mapped_column(String(255))
    auth_port: Mapped[int] = mapped_column(Integer, default=1812)
    acct_port: Mapped[int] = mapped_column(Integer, default=1813)
    secret_enc: Mapped[str] = mapped_column(Text)
    coa_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    ad_hoc: Mapped[bool] = mapped_column(Boolean, default=False)
    attributes_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


class Certificate(Base):
    __tablename__ = "certificates"

    # type: trusted | identity_user | identity_machine
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    friendly_name: Mapped[str] = mapped_column(String(160))
    type: Mapped[str] = mapped_column(String(32), index=True)
    content_pem: Mapped[str] = mapped_column(Text)
    key_pem_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject: Mapped[str] = mapped_column(String(400), default="")
    issuer: Mapped[str] = mapped_column(String(400), default="")
    serial: Mapped[str] = mapped_column(String(80), default="")
    thumbprint: Mapped[str] = mapped_column(String(80), default="")
    valid_from: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    valid_to: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    created: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)

    @property
    def is_expired(self) -> bool:
        if self.valid_to is None:
            return False
        return self.valid_to.replace(tzinfo=dt.timezone.utc) < _now()


class Job(Base):
    __tablename__ = "jobs"

    # status: queued | running | done | failed | cancelled
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120))
    bulk: Mapped[str] = mapped_column(String(120), default="none", index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"))
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    total: Mapped[int] = mapped_column(Integer, default=1)
    completed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    params_json: Mapped[dict] = mapped_column(JSON, default=dict)
    started: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    finished: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    server: Mapped["Server"] = relationship()
    sessions: Mapped[list["Session"]] = relationship(
        back_populates="job", cascade="all, delete-orphan")

    @property
    def percentage(self) -> int:
        if not self.total:
            return 0
        return int(100 * (self.completed + self.failed) / self.total)


class BulkOperation(Base):
    """Progress for an action applied to many sessions at once."""

    __tablename__ = "bulk_operations"

    # kind:   acct_start | acct_interim | acct_stop | reauth | delete
    # status: running | done | failed | cancelled
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(20))
    scope: Mapped[str] = mapped_column(String(120), default="")
    total: Mapped[int] = mapped_column(Integer, default=0)
    done: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="running", index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    started: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    finished: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def percentage(self) -> int:
        if not self.total:
            return 0
        return int(100 * (self.done + self.failed) / self.total)


class Session(Base):
    __tablename__ = "sessions"

    # status: accepted | rejected | error | timeout
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), index=True)
    bulk: Mapped[str] = mapped_column(String(120), default="none", index=True)
    server_id: Mapped[str] = mapped_column(String(36), index=True)

    mac: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    username: Mapped[str] = mapped_column(String(255), default="")
    machine_name: Mapped[str] = mapped_column(String(255), default="")

    # Required by accounting and CoA (plan section 4). Captured now even though
    # nothing reads them yet: sessions generated without these are useless for
    # accounting later.
    acct_session_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    class_blob: Mapped[str] = mapped_column(Text, default="")   # RADIUS Class, hex
    state_blob: Mapped[str] = mapped_column(Text, default="")   # RADIUS State, hex

    status: Mapped[str] = mapped_column(String(20), default="error", index=True)
    # accounting lifecycle, independent of the authentication result
    acct_status: Mapped[str] = mapped_column(String(20), default="", index=True)
    acct_session_time: Mapped[int] = mapped_column(Integer, default=0)
    reauth_count: Mapped[int] = mapped_column(Integer, default=0)
    # Session lifetime, RFC 2865 sections 5.27 and 5.29. termination_action
    # 1 = RADIUS-Request (re-authenticate), anything else = terminate.
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True,
                                                           index=True)
    lifetime_seconds: Mapped[int] = mapped_column(Integer, default=0)
    termination_action: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(default=0.0)
    started: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    changed: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)

    request_attrs_json: Mapped[dict] = mapped_column(JSON, default=dict)
    reply_attrs_json: Mapped[dict] = mapped_column(JSON, default=dict)
    log_json: Mapped[list] = mapped_column(JSON, default=list)

    job: Mapped["Job"] = relationship(back_populates="sessions")
