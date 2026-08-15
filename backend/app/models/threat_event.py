from sqlalchemy import Column, BigInteger, String, Float, SmallInteger, Text, DateTime, UniqueConstraint, func
from app.database import Base

class ThreatEvent(Base):
    __tablename__ = "threat_events"
    __table_args__ = (
        UniqueConstraint("server_id", "ingest_event_id", name="uq_threat_events_server_ingest_event"),
    )

    id = Column(BigInteger, primary_key=True, index=True)
    ingest_event_id = Column(String(64), nullable=True)
    server_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    source_country = Column(String(2))
    source_lat = Column(Float)
    source_lon = Column(Float)
    dest_ip = Column(String(45))
    dest_country = Column(String(2))
    dest_lat = Column(Float)
    dest_lon = Column(Float)
    method = Column(String(10))
    path = Column(Text)
    status_code = Column(SmallInteger)
    bytes_sent = Column(BigInteger)
    request_time = Column(Float)
    user_agent = Column(Text)
    host = Column(String(255))
    abuse_score = Column(SmallInteger)
    attack_type = Column(String(32))
    severity = Column(String(16))
    anomaly_score = Column(Float)
    explanation = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
