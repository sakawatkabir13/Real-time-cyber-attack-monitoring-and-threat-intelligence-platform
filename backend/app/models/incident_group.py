"""Suggested related incidents, not attribution to a common attacker."""

import uuid
from sqlalchemy import Column, DateTime, Integer, JSON, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class IncidentGroup(Base):
    __tablename__ = "incident_groups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    server_id = Column(String(64), nullable=False, index=True)
    attack_type = Column(String(32), nullable=False)
    path = Column(Text)
    source_count = Column(Integer, nullable=False)
    alert_count = Column(Integer, nullable=False)
    source_ips = Column(JSON, nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    explanation = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
