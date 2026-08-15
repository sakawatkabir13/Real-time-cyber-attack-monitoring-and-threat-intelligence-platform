from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class ThreatEventBase(BaseModel):
    server_id: str
    timestamp: datetime
    source_ip: str
    source_country: Optional[str] = None
    source_lat: Optional[float] = None
    source_lon: Optional[float] = None
    dest_ip: Optional[str] = None
    dest_country: Optional[str] = None
    dest_lat: Optional[float] = None
    dest_lon: Optional[float] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    request_time: Optional[float] = None
    user_agent: Optional[str] = None
    host: Optional[str] = None
    abuse_score: Optional[int] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    anomaly_score: Optional[float] = None
    explanation: Optional[str] = None

class ThreatEventCreate(ThreatEventBase):
    pass

class ThreatEventResponse(ThreatEventBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
