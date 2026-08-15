"""Adopt the application schema and add ingestion idempotency."""

from alembic import op
from sqlalchemy import Column, String, inspect

from app.database import Base
from app import models  # noqa: F401

revision = "0001_managed_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    threat_exists = "threat_events" in inspector.get_table_names()
    existing_columns = (
        {column["name"] for column in inspector.get_columns("threat_events")}
        if threat_exists
        else set()
    )

    Base.metadata.create_all(bind=bind, checkfirst=True)
    if threat_exists and "ingest_event_id" not in existing_columns:
        op.add_column("threat_events", Column("ingest_event_id", String(64), nullable=True))

    inspector = inspect(bind)
    constraint_names = {
        item["name"]
        for item in inspector.get_unique_constraints("threat_events")
        if item.get("name")
    }
    if "uq_threat_events_server_ingest_event" not in constraint_names:
        op.create_unique_constraint(
            "uq_threat_events_server_ingest_event",
            "threat_events",
            ["server_id", "ingest_event_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "threat_events" not in inspector.get_table_names():
        return
    constraint_names = {
        item["name"]
        for item in inspector.get_unique_constraints("threat_events")
        if item.get("name")
    }
    if "uq_threat_events_server_ingest_event" in constraint_names:
        op.drop_constraint(
            "uq_threat_events_server_ingest_event",
            "threat_events",
            type_="unique",
        )
    columns = {column["name"] for column in inspector.get_columns("threat_events")}
    if "ingest_event_id" in columns:
        op.drop_column("threat_events", "ingest_event_id")
