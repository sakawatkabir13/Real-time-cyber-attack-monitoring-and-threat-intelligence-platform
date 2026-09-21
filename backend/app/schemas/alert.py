from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


ReviewVerdict = Literal["confirmed_malicious", "legitimate", "misconfiguration", "uncertain"]


class AlertReviewRequest(BaseModel):
    verdict: ReviewVerdict
    notes: str = Field(min_length=1, max_length=4000, pattern=r"\S")
    expected_version: int = Field(ge=0)


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
    verdict: str
    review_version: int
    reviewed_at: datetime | None
    incident_group_id: UUID | None
