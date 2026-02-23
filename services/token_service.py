from utils.jwt import decode_token, get_token_type, get_token_subject
from utils.response import error
from utils.status_code import AuthStatus


class TokenService:

    @staticmethod
    def verify_token(token: str, expected_type: str):
        try:
            payload = decode_token(token)
        except Exception:
            return None, error(
                AuthStatus.TOKEN_INVALID,
                "Token is invalid or expired."
            )

        if get_token_type(payload) != expected_type:
            return None, error(
                AuthStatus.TOKEN_WRONG_TYPE,
                "Token type is not valid for this operation."
            )

        subject = get_token_subject(payload)
        if not subject:
            return None, error(
                AuthStatus.TOKEN_INVALID,
                "Token payload is malformed."
            )

        return payload, None