import os
import re

from fastapi import HTTPException


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-\u0E00-\u0E7F]{3,50}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def test_mode_enabled() -> bool:
    return os.getenv("TEST_MODE", "FALSE").upper() == "TRUE"


def require_test_mode() -> None:
    if not test_mode_enabled():
        raise HTTPException(status_code=404, detail="Not found")


def test_identity() -> tuple[str, str]:
    username = os.getenv("TEST_USER_USERNAME", "").strip()
    email = os.getenv("TEST_USER_EMAIL", "").strip().lower()
    if not USERNAME_PATTERN.fullmatch(username) or not EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=503, detail="Test user identity is not configured.")
    return username, email
