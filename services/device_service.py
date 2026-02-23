import hashlib
from cores.redis import redis_client

TRUST_DEVICE_TTL = 60 * 60 * 24 * 7

class DeviceService:

    @staticmethod
    def generate_device_hash(user_agent: str, ip: str):
        raw = f"{user_agent}:{ip}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def is_trusted(cls, uid: int, user_agent: str, ip: str):
        device_hash = cls.generate_device_hash(user_agent, ip)
        return redis_client.exists(f"device:{uid}:{device_hash}")

    @classmethod
    def remember_device(cls, uid: int, user_agent: str, ip: str):
        device_hash = cls.generate_device_hash(user_agent, ip)
        redis_client.setex(
            f"device:{uid}:{device_hash}",
            TRUST_DEVICE_TTL,
            "trusted"
        )