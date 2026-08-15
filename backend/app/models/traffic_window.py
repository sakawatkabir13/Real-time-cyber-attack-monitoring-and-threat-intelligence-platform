from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from app.database import Base

class TrafficWindow(Base):
    __tablename__ = "traffic_windows"
    __table_args__ = (
        UniqueConstraint(
            "server_id",
            "scope",
            "entity_key",
            "window_start",
            "window_seconds",
            name="uq_traffic_window_entity_period",
        ),
    )

    id = Column(BigInteger, primary_key=True, index=True)
    server_id = Column(String(64), nullable=False, index=True)
    scope = Column(String(16), nullable=False, default="server", index=True)
    entity_key = Column(String(64), nullable=False, default="server")
    window_start = Column(DateTime(timezone=True), nullable=False, index=True)
    window_seconds = Column(SmallInteger, nullable=False)
    source_ip_hash = Column(String(64))
    path = Column(Text)
    country = Column(String(2))
    request_count = Column(Integer)
    bytes_total = Column(BigInteger)
    status_2xx = Column(Integer)
    status_3xx = Column(Integer)
    status_4xx = Column(Integer)
    status_5xx = Column(Integer)
    avg_request_time = Column(Float)
    unique_user_agents = Column(Integer)
    unique_ips = Column(Integer)
    unique_paths = Column(Integer)
    new_ip_ratio = Column(Float)
    top_path_share = Column(Float)
    request_rate = Column(Float)
    status_4xx_ratio = Column(Float)
    status_5xx_ratio = Column(Float)
    avg_bytes = Column(Float)
    reputation_score = Column(Float)
    reporter_count = Column(Integer)
    community_reports = Column(Integer)
    rule_threat_count = Column(Integer, nullable=False, default=0)
    is_training_eligible = Column(Boolean, nullable=False, default=True)
    anomaly_score = Column(Float)
    model_version = Column(String(64))
    anomaly_explanation = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
