import uuid

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text, func
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class MlModelRun(Base):
    __tablename__ = "ml_model_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_version = Column(String(64), nullable=False, index=True)
    scope = Column(String(16), nullable=False, index=True)
    server_id = Column(String(64), nullable=False, index=True)
    status = Column(String(16), nullable=False)
    sample_count = Column(Integer, nullable=False, default=0)
    contamination = Column(Float)
    window_start = Column(DateTime(timezone=True))
    window_end = Column(DateTime(timezone=True))
    metrics = Column(JSON)
    error = Column(Text)
    trained_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
