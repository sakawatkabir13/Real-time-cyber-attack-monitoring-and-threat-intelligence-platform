from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import uuid

class DdosAlert(Base):
    __tablename__ = "ddos_alerts"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_ddos_alerts_dedupe_key"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    server_id = Column(String(64), nullable=False, index=True)
    source_ip = Column(String(45), index=True)
    dedupe_key = Column(String(64), index=True)
    first_event_id = Column(BigInteger)
    latest_event_id = Column(BigInteger)
    start_time = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    end_time = Column(DateTime(timezone=True))
    attack_type = Column(String(32), nullable=False)
    severity = Column(String(16), nullable=False)
    status = Column(String(32), nullable=False, default="new", index=True)
    detection_method = Column(String(16), nullable=False)
    trigger_reason = Column(Text, nullable=False)
    top_source_ips = Column(JSON)
    top_paths = Column(JSON)
    top_countries = Column(JSON)
    request_rate = Column(Float)
    confidence = Column(Float)
    occurrence_count = Column(Integer, nullable=False, default=1)
    acknowledged_at = Column(DateTime(timezone=True))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
