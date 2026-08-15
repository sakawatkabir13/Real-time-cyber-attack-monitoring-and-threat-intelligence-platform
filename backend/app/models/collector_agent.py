from sqlalchemy import Column, DateTime, Integer, String, Text, func

from app.database import Base


class CollectorAgent(Base):
    __tablename__ = "collector_agents"

    server_id = Column(String(64), primary_key=True)
    desired_state = Column(String(16), nullable=False, default="running")
    reported_state = Column(String(16), nullable=False, default="running")
    command_version = Column(Integer, nullable=False, default=0)
    spool_depth = Column(Integer, nullable=False, default=0)
    agent_version = Column(String(32))
    last_error = Column(Text)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
