from typing import Any, Optional


def success(status: str, message: str, data: Optional[Any] = None):
    return {
        "success": True,
        "status": status,
        "message": message,
        "data": data
    }


def error(status: str, message: str, data: Optional[Any] = None):
    return {
        "success": False,
        "status": status,
        "message": message,
        "data": data
    }