import re

from sqlalchemy import func

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def normalize_email(email: str) -> str:
    email = email.strip().lower()
    if "@" not in email:
        return email
    local, _, domain = email.partition("@")
    plus_index = local.find("+")
    if plus_index != -1:
        local = local[:plus_index]
    return f"{local}@{domain}"


def normalized_email_expr(column):
    local = func.split_part(column, "@", 1)
    domain = func.split_part(column, "@", 2)
    local_no_plus = func.split_part(local, "+", 1)
    return func.lower(func.concat(local_no_plus, "@", domain))
