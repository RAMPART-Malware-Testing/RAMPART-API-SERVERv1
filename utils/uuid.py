from uuid import UUID


def parse_uuid(value) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ValueError("Invalid UUID")
    return UUID(value)
