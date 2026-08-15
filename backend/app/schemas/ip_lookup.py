from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class IPLookupBase(BaseModel):
    ip_address: str
    abuse_score: Optional[int] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    usage_type: Optional[str] = None
    is_tor: bool = False
    is_vpn: bool = False

class IPLookupCreate(IPLookupBase):
    pass

class IPLookupResponse(IPLookupBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    last_updated: datetime
