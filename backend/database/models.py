"""
Persistence models for analyzed emails and SOC incidents.

These models are wired into the threat detection pipeline via
backend/main.py's execute_analysis_pipeline() to store analyzed emails,
incident tracking records, and triage history for the SOC queue.
"""

from datetime import datetime, timezone
from enum import Enum


def _utcnow() -> datetime:
    """Return current UTC time as a timezone-naive datetime (SQLite-compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

try:
    from .db import Base
except ImportError:
    from database.db import Base


class IncidentStatus(str, Enum):
    NEW = "new"
    OPEN = "open"
    IN_REVIEW = "in_review"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class AnalyzedEmail(Base):
    __tablename__ = "analyzed_emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sender: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    recipient: Mapped[str | None] = mapped_column(String(512), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(998), nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    evidence_level: Mapped[str | None] = mapped_column(String(32), nullable=True)

    phishing_probability: Mapped[int | None] = mapped_column(Integer, nullable=True)
    header_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    raw_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    received_chain: Mapped[list | None] = mapped_column(JSON, nullable=True)
    analysis_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=_utcnow,
        index=True,
    )

    incidents: Mapped[list["Incident"]] = relationship(
        back_populates="analyzed_email",
        cascade="all, delete-orphan",
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    analyzed_email_id: Mapped[int] = mapped_column(
        ForeignKey("analyzed_emails.id"),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[IncidentStatus] = mapped_column(
        SQLEnum(IncidentStatus, values_callable=lambda enum: [item.value for item in enum]),
        nullable=False,
        default=IncidentStatus.NEW,
        index=True,
    )
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=_utcnow,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    analyzed_email: Mapped[AnalyzedEmail] = relationship(back_populates="incidents")
