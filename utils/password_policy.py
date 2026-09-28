import re

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

_PASSWORD_UPPER_RE = re.compile(r"[A-Z]")
_PASSWORD_LOWER_RE = re.compile(r"[a-z]")
_PASSWORD_DIGIT_RE = re.compile(r"[0-9]")
_PASSWORD_SPECIAL_RE = re.compile(r"[!@#$%^&*(),.?\":{}|<>]")


def validate_password_policy(value: str) -> str | None:
    if len(value) < PASSWORD_MIN_LENGTH:
        return f"รหัสผ่านต้องมีความยาวอย่างน้อย {PASSWORD_MIN_LENGTH} ตัวอักษร"
    if len(value) > PASSWORD_MAX_LENGTH:
        return f"รหัสผ่านต้องยาวไม่เกิน {PASSWORD_MAX_LENGTH} ตัวอักษร"
    if not _PASSWORD_UPPER_RE.search(value):
        return "รหัสผ่านต้องมีตัวอักษรพิมพ์ใหญ่อย่างน้อย 1 ตัว"
    if not _PASSWORD_LOWER_RE.search(value):
        return "รหัสผ่านต้องมีตัวอักษรพิมพ์เล็กอย่างน้อย 1 ตัว"
    if not _PASSWORD_DIGIT_RE.search(value):
        return "รหัสผ่านต้องมีตัวเลขอย่างน้อย 1 ตัว"
    if not _PASSWORD_SPECIAL_RE.search(value):
        return "รหัสผ่านต้องมีอักขระพิเศษอย่างน้อย 1 ตัว"
    return None
