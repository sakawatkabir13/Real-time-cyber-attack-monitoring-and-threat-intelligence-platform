from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    server_id: str
    source_ip: str | None
    attack_type: str
    severity: str
    status: str
    trigger_reason: str
    confidence: float | None
    occurrence_count: int
    start_time: datetime
    last_seen: datetime
    acknowledged_at: datetime | None
