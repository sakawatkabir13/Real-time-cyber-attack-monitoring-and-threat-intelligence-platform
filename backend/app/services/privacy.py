import hmac
import hashlib
from app.config import settings

def hash_ip(ip: str) -> str:
    # Use a secret key to deterministically hash the IP for privacy
    secret = getattr(settings, "SECRET_KEY", "default-vanguard-secret").encode()
    return hmac.new(secret, ip.encode(), hashlib.sha256).hexdigest()[:12]
