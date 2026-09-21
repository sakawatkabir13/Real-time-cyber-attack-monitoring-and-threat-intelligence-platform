"""Append-only operator verdict history. Acknowledgment is not a verdict."""

import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class AlertReview(Base):
    __tablename__ = "alert_reviews"
    __table_args__ = (UniqueConstraint("alert_id", "version", name="uq_alert_review_version"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("ddos_alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    verdict = Column(String(32), nullable=False)
    notes = Column(Text, nullable=False)
    # Dashboard has a shared operator login, not individual user identities.
    reviewed_by = Column(String(64), nullable=False, default="dashboard_operator")
    reviewed_at = Column(DateTime(timezone=True), server_default=func.now())
