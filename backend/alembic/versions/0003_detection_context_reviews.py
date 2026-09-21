"""Behavioral measurements, investigation history, and related-incident groups."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base
from app import models  # noqa: F401

revision = "0003_detection_context"
down_revision = "0002_behavioral_pipeline"
branch_labels = None
depends_on = None


def _add_missing(table: str, columns: list[sa.Column]) -> None:
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}
    for column in columns:
        if column.name not in existing:
            op.add_column(table, column)


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.tables["incident_groups"].create(bind, checkfirst=True)
    _add_missing("traffic_windows", [
        sa.Column("feature_schema", sa.Integer(), nullable=False, server_default="2"),
        *[sa.Column(name, sa.Float()) for name in (
            "request_time_coverage", "peak_second_requests", "burst_ratio",
            "rate_change_ratio", "previous_window_present", "failed_auth_ratio", "max_path_unique_ips",
        )],
    ])
    _add_missing("ddos_alerts", [
        sa.Column("verdict", sa.String(32), nullable=False, server_default="unreviewed"),
        sa.Column("review_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("incident_group_id", UUID(as_uuid=True)),
    ])
    inspector = sa.inspect(bind)
    if not any(fk["constrained_columns"] == ["incident_group_id"] for fk in inspector.get_foreign_keys("ddos_alerts")):
        op.create_foreign_key("fk_alert_incident_group", "ddos_alerts", "incident_groups", ["incident_group_id"], ["id"], ondelete="SET NULL")
    if "ix_ddos_alerts_incident_group_id" not in {i["name"] for i in inspector.get_indexes("ddos_alerts")}:
        op.create_index("ix_ddos_alerts_incident_group_id", "ddos_alerts", ["incident_group_id"])
    Base.metadata.tables["alert_reviews"].create(bind, checkfirst=True)
    op.alter_column("threat_events", "source_ip", existing_type=sa.String(45), nullable=True)


def downgrade() -> None:
    # Preserve history, reviews, and nullable server-wide source identities.
    # A destructive downgrade is deliberately not provided.
    raise RuntimeError("This migration preserves security history; restore a pre-upgrade backup to roll back.")
