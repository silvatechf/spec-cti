"""
Database engine, session management, and ORM models for CyberLab-Enterprise.

Uses SQLAlchemy 2.0-style declarative models. Alembic migrations live in
`alembic/` at the project root (not shown here) and are generated from
this metadata via `alembic revision --autogenerate`.
"""

from __future__ import annotations

import enum
from contextlib import contextmanager
from datetime import datetime
from typing import Generator, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

from src.core.config import get_settings

settings = get_settings()

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    """Base class for all ORM models."""


# ─────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, enum.Enum):
    DETECTED = "detected"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class FlagCategory(str, enum.Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    PRIVESC = "privesc"
    FORENSICS = "forensics"
    IR = "ir"


# ─────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────

class Account(Base):
    """A seeded (fictional) user account on the simulated corporate network."""

    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    department: Mapped[Optional[str]] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_former_employee: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    reused_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Host(Base):
    """A discoverable host/container within the lab network."""

    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(128), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    os_family: Mapped[Optional[str]] = mapped_column(String(64))
    role: Mapped[Optional[str]] = mapped_column(String(64))
    is_online: Mapped[bool] = mapped_column(Boolean, default=True)

    findings: Mapped[list["Finding"]] = relationship(back_populates="host")


class Finding(Base):
    """A vulnerability or misconfiguration discovered against a Host."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text)
    cve_id: Mapped[Optional[str]] = mapped_column(String(32))
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.INFO)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_confirmed_exploitable: Mapped[bool] = mapped_column(Boolean, default=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    host: Mapped["Host"] = relationship(back_populates="findings")


class SecurityEvent(Base):
    """A raw or normalized security event ingested from container logs."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_host: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(64))
    raw_message: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.INFO)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Incident(Base):
    """A tracked incident moving through the IR lifecycle."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus), default=IncidentStatus.DETECTED
    )
    affected_host: Mapped[Optional[str]] = mapped_column(String(128))
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    eradicated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    recovered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    timeline_json: Mapped[Optional[str]] = mapped_column(Text)


class CTFFlag(Base):
    """A CTF flag hidden somewhere in the lab, with scoring metadata."""

    __tablename__ = "ctf_flags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    flag_value: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    category: Mapped[FlagCategory] = mapped_column(Enum(FlagCategory), nullable=False)
    description: Mapped[str] = mapped_column(Text)
    base_points: Mapped[int] = mapped_column(Integer, default=100)
    difficulty: Mapped[str] = mapped_column(String(32), default="easy")
    hidden_location: Mapped[str] = mapped_column(String(256))


class CTFSubmission(Base):
    """A player's submission attempt against a CTFFlag."""

    __tablename__ = "ctf_submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    player_name: Mapped[str] = mapped_column(String(64), nullable=False)
    flag_id: Mapped[int] = mapped_column(ForeignKey("ctf_flags.id"))
    correct: Mapped[bool] = mapped_column(Boolean, default=False)
    points_awarded: Mapped[int] = mapped_column(Integer, default=0)
    hints_used: Mapped[int] = mapped_column(Integer, default=0)
    submitted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


def init_db() -> None:
    """Create all tables. Idempotent; safe to call on every startup."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context-managed database session for scripts and services."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency-injectable session generator."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
