from sqlalchemy import Column, String, SmallInteger, Text, DateTime, func, JSON, Boolean, Integer
from app.database import Base

class IpReputation(Base):
    __tablename__ = "ip_reputation_cache"

    ip_address = Column(String(45), primary_key=True)
    abuse_score = Column(SmallInteger)
    isp = Column(Text)
    asn = Column(String(32))
    domain = Column(Text)
    country_code = Column(String(2))
    usage_type = Column(String(64))
    is_tor = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    total_reports = Column(Integer) # Note: changed to Integer
    last_reported = Column(DateTime(timezone=True))
    categories = Column(JSON)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), index=True)
