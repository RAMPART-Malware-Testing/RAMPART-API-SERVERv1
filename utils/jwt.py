import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import jwt, JWTError

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set in environment variables")

def create_token(
    *,
    subject: str,
    token_type: str,
    expires_minutes: int,
    extra_payload: Optional[Dict[str, Any]] = None
) -> str:
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)

    payload: Dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "exp": expire,
        "iat": datetime.utcnow()
    }

    if extra_payload:
        payload.update(extra_payload)

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )
        return payload
    except JWTError as e:
        return None

def get_token_subject(payload: Dict[str, Any]) -> str:
    if not payload:
        return None
    return payload.get("sub")

def get_token_type(payload: Dict[str, Any]) -> str:
    if not payload:
        return None
    return payload.get("type")
