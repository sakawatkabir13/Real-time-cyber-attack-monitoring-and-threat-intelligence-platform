"""
Ingest schemas — data models for log ingestion.

LogEntry is the validated internal representation of a parsed HTTP log line.
The external AgentBatch schema lives in app.routers.ingest because it accepts
raw collector dictionaries before parsing.
"""

from pydantic import BaseModel, Field


class LogEntry(BaseModel):
    """
    A single structured log entry after parsing a raw nginx/apache log line.
    All fields are required — the ingest router guarantees these are populated
    before constructing a LogEntry.
    """
    timestamp: str
    source_ip: str
    method: str
    path: str
    status_code: int
    bytes_sent: int
    # Unknown is not a zero-second response. Durations are always seconds.
    request_time: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    user_agent: str
    host: str
    server_id: str
    event_id: str | None = None
