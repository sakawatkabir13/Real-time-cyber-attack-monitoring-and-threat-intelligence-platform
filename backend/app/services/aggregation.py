from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.threat_event import ThreatEvent
from datetime import datetime, timedelta, timezone

async def get_attack_stats(db: AsyncSession, hours: int = 24):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = select(ThreatEvent.attack_type, func.count(ThreatEvent.id)).where(ThreatEvent.timestamp >= cutoff).group_by(ThreatEvent.attack_type)
    result = await db.execute(query)
    return [{"attack_type": row[0], "count": row[1]} for row in result.all()]

async def get_top_ips(db: AsyncSession, limit: int = 10):
    query = select(ThreatEvent.source_ip, func.count(ThreatEvent.id)).group_by(ThreatEvent.source_ip).order_by(func.count(ThreatEvent.id).desc()).limit(limit)
    result = await db.execute(query)
    return [{"ip": row[0], "count": row[1]} for row in result.all()]
