"""Add behavioral ML windows, persistent incidents, and collector state."""

from alembic import op
import sqlalchemy as sa

from app.database import Base
from app import models  # noqa: F401


revision = "0002_behavioral_pipeline"
down_revision = "0001_managed_schema"
branch_labels = None
depends_on = None


def _column_names(inspector: sa.Inspector, table: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table)}


def _add_missing_columns(table: str, definitions: dict[str, sa.Column]) -> None:
    inspector = sa.inspect(op.get_bind())
    existing = _column_names(inspector, table)
    for name, column in definitions.items():
        if name not in existing:
            op.add_column(table, column)


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())

    for table_name in ("collector_agents", "ml_model_runs"):
        if table_name not in tables:
            Base.metadata.tables[table_name].create(bind=bind, checkfirst=True)

    _add_missing_columns(
        "ml_model_runs",
        {
            "server_id": sa.Column(
                "server_id", sa.String(64), nullable=False, server_default="unknown"
            )
        },
    )

    _add_missing_columns(
        "traffic_windows",
        {
            "scope": sa.Column(
                "scope", sa.String(16), nullable=False, server_default="server"
            ),
            "entity_key": sa.Column(
                "entity_key", sa.String(64), nullable=False, server_default="server"
            ),
            "unique_paths": sa.Column("unique_paths", sa.Integer()),
            "new_ip_ratio": sa.Column("new_ip_ratio", sa.Float()),
            "top_path_share": sa.Column("top_path_share", sa.Float()),
            "request_rate": sa.Column("request_rate", sa.Float()),
            "status_4xx_ratio": sa.Column("status_4xx_ratio", sa.Float()),
            "status_5xx_ratio": sa.Column("status_5xx_ratio", sa.Float()),
            "avg_bytes": sa.Column("avg_bytes", sa.Float()),
            "reputation_score": sa.Column("reputation_score", sa.Float()),
            "reporter_count": sa.Column("reporter_count", sa.Integer()),
            "community_reports": sa.Column("community_reports", sa.Integer()),
            "rule_threat_count": sa.Column(
                "rule_threat_count", sa.Integer(), nullable=False, server_default="0"
            ),
            "is_training_eligible": sa.Column(
                "is_training_eligible", sa.Boolean(), nullable=False, server_default=sa.true()
            ),
            "model_version": sa.Column("model_version", sa.String(64)),
            "anomaly_explanation": sa.Column("anomaly_explanation", sa.Text()),
        },
    )

    # Preserve useful legacy source-window identity before enforcing the new
    # composite key. If an old installation contains duplicate rows, retain all
    # of them with a stable suffixed entity key rather than deleting history.
    op.execute(
        """
        UPDATE traffic_windows
        SET scope = CASE
                WHEN source_ip_hash IS NOT NULL AND source_ip_hash <> ''
                    THEN 'source'
                ELSE 'server'
            END,
            entity_key = CASE
                WHEN source_ip_hash IS NOT NULL AND source_ip_hash <> ''
                    THEN source_ip_hash
                ELSE 'server'
            END
        """
    )
    op.execute(
        """
        WITH duplicates AS (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY server_id, scope, entity_key,
                                    window_start, window_seconds
                       ORDER BY id
                   ) AS duplicate_number
            FROM traffic_windows
        )
        UPDATE traffic_windows AS tw
        SET entity_key = left(tw.entity_key, 40) || ':' || tw.id::text
        FROM duplicates
        WHERE tw.id = duplicates.id AND duplicates.duplicate_number > 1
        """
    )

    inspector = sa.inspect(bind)
    traffic_constraints = {
        item["name"]
        for item in inspector.get_unique_constraints("traffic_windows")
        if item.get("name")
    }
    if "uq_traffic_window_entity_period" not in traffic_constraints:
        op.create_unique_constraint(
            "uq_traffic_window_entity_period",
            "traffic_windows",
            ["server_id", "scope", "entity_key", "window_start", "window_seconds"],
        )
    traffic_indexes = {
        item["name"] for item in sa.inspect(bind).get_indexes("traffic_windows")
    }
    if "ix_traffic_windows_scope" not in traffic_indexes:
        op.create_index("ix_traffic_windows_scope", "traffic_windows", ["scope"])

    _add_missing_columns(
        "ddos_alerts",
        {
            "source_ip": sa.Column("source_ip", sa.String(45)),
            "dedupe_key": sa.Column("dedupe_key", sa.String(64)),
            "first_event_id": sa.Column("first_event_id", sa.BigInteger()),
            "latest_event_id": sa.Column("latest_event_id", sa.BigInteger()),
            "last_seen": sa.Column("last_seen", sa.DateTime(timezone=True)),
            "occurrence_count": sa.Column(
                "occurrence_count", sa.Integer(), nullable=False, server_default="1"
            ),
            "acknowledged_at": sa.Column(
                "acknowledged_at", sa.DateTime(timezone=True)
            ),
        },
    )
    op.execute("UPDATE ddos_alerts SET last_seen = start_time WHERE last_seen IS NULL")
    op.alter_column("ddos_alerts", "last_seen", nullable=False)

    inspector = sa.inspect(bind)
    alert_constraints = {
        item["name"]
        for item in inspector.get_unique_constraints("ddos_alerts")
        if item.get("name")
    }
    if "uq_ddos_alerts_dedupe_key" not in alert_constraints:
        op.create_unique_constraint(
            "uq_ddos_alerts_dedupe_key", "ddos_alerts", ["dedupe_key"]
        )
    alert_indexes = {item["name"] for item in sa.inspect(bind).get_indexes("ddos_alerts")}
    if "ix_ddos_alerts_source_ip" not in alert_indexes:
        op.create_index("ix_ddos_alerts_source_ip", "ddos_alerts", ["source_ip"])
    if "ix_ddos_alerts_last_seen" not in alert_indexes:
        op.create_index("ix_ddos_alerts_last_seen", "ddos_alerts", ["last_seen"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "ddos_alerts" in inspector.get_table_names():
        indexes = {item["name"] for item in inspector.get_indexes("ddos_alerts")}
        for index_name in ("ix_ddos_alerts_last_seen", "ix_ddos_alerts_source_ip"):
            if index_name in indexes:
                op.drop_index(index_name, table_name="ddos_alerts")
        constraints = {
            item["name"]
            for item in inspector.get_unique_constraints("ddos_alerts")
            if item.get("name")
        }
        if "uq_ddos_alerts_dedupe_key" in constraints:
            op.drop_constraint(
                "uq_ddos_alerts_dedupe_key", "ddos_alerts", type_="unique"
            )
        for column in (
            "acknowledged_at",
            "occurrence_count",
            "last_seen",
            "latest_event_id",
            "first_event_id",
            "dedupe_key",
            "source_ip",
        ):
            if column in _column_names(sa.inspect(bind), "ddos_alerts"):
                op.drop_column("ddos_alerts", column)

    if "traffic_windows" in inspector.get_table_names():
        indexes = {
            item["name"] for item in sa.inspect(bind).get_indexes("traffic_windows")
        }
        if "ix_traffic_windows_scope" in indexes:
            op.drop_index("ix_traffic_windows_scope", table_name="traffic_windows")
        constraints = {
            item["name"]
            for item in sa.inspect(bind).get_unique_constraints("traffic_windows")
            if item.get("name")
        }
        if "uq_traffic_window_entity_period" in constraints:
            op.drop_constraint(
                "uq_traffic_window_entity_period", "traffic_windows", type_="unique"
            )
        for column in (
            "anomaly_explanation",
            "model_version",
            "is_training_eligible",
            "rule_threat_count",
            "community_reports",
            "reporter_count",
            "reputation_score",
            "avg_bytes",
            "status_5xx_ratio",
            "status_4xx_ratio",
            "request_rate",
            "top_path_share",
            "new_ip_ratio",
            "unique_paths",
            "entity_key",
            "scope",
        ):
            if column in _column_names(sa.inspect(bind), "traffic_windows"):
                op.drop_column("traffic_windows", column)

    for table_name in ("ml_model_runs", "collector_agents"):
        if table_name in sa.inspect(bind).get_table_names():
            op.drop_table(table_name)
