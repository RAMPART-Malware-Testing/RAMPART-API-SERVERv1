import pytest

from services import otp_service as otp_service_module
from services.otp_service import MAX_OTP_ATTEMPTS, OTP_TTL_SECONDS, OTPService


class FakeRedis:
    def __init__(self):
        self.store: dict[str, tuple[str, int]] = {}

    def setex(self, key, ttl, value):
        self.store[key] = (str(value), ttl)

    def get(self, key):
        entry = self.store.get(key)
        return entry[0] if entry else None

    def delete(self, key):
        self.store.pop(key, None)

    def ttl(self, key):
        entry = self.store.get(key)
        return entry[1] if entry else -2


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(otp_service_module, "redis_client", fake)
    return fake


def test_verify_otp_missing_session_is_expired(fake_redis):
    outcome, detail = OTPService.verify_otp("login", "no-such-token", "123456")
    assert outcome == "expired"
    assert detail is None


def test_verify_otp_correct_code_is_ok(fake_redis):
    fake_redis.setex(OTPService._key("login", "tok"), OTP_TTL_SECONDS, "123456")
    outcome, detail = OTPService.verify_otp("login", "tok", "123456")
    assert outcome == "ok"
    assert detail is None


def test_verify_otp_wrong_code_decrements_remaining_attempts(fake_redis):
    fake_redis.setex(OTPService._key("login", "tok"), OTP_TTL_SECONDS, "123456")

    outcome, remaining = OTPService.verify_otp("login", "tok", "000000")
    assert outcome == "wrong"
    assert remaining == MAX_OTP_ATTEMPTS - 1

    outcome, remaining = OTPService.verify_otp("login", "tok", "111111")
    assert outcome == "wrong"
    assert remaining == MAX_OTP_ATTEMPTS - 2


def test_verify_otp_locks_out_after_max_attempts(fake_redis):
    fake_redis.setex(OTPService._key("login", "tok"), OTP_TTL_SECONDS, "123456")

    for expected_remaining in range(MAX_OTP_ATTEMPTS - 1, -1, -1):
        outcome, remaining = OTPService.verify_otp("login", "tok", "wrong-guess")
        assert outcome == "wrong"
        assert remaining == expected_remaining

    outcome, detail = OTPService.verify_otp("login", "tok", "999999")
    assert outcome == "locked"
    assert isinstance(detail, int)
    assert detail > 0


def test_verify_otp_locked_rejects_even_the_correct_code(fake_redis):
    key = OTPService._key("login", "tok")
    fake_redis.setex(key, OTP_TTL_SECONDS, "123456")

    for _ in range(MAX_OTP_ATTEMPTS):
        OTPService.verify_otp("login", "tok", "wrong-guess")

    outcome, _ = OTPService.verify_otp("login", "tok", "123456")
    assert outcome == "locked"


def test_verify_otp_actions_are_isolated(fake_redis):
    fake_redis.setex(OTPService._key("login", "shared-token"), OTP_TTL_SECONDS, "111111")
    fake_redis.setex(OTPService._key("register", "shared-token"), OTP_TTL_SECONDS, "222222")

    OTPService.verify_otp("login", "shared-token", "000000")

    outcome, _ = OTPService.verify_otp("register", "shared-token", "222222")
    assert outcome == "ok"


def test_clear_otp_session_removes_both_value_and_attempts(fake_redis):
    key = OTPService._key("login", "tok")
    attempts_key = OTPService._attempts_key("login", "tok")
    fake_redis.setex(key, OTP_TTL_SECONDS, "123456")
    fake_redis.setex(attempts_key, OTP_TTL_SECONDS, "3")

    OTPService.clear_otp_session("login", "tok", "some-uid")

    assert fake_redis.get(key) is None
    assert fake_redis.get(attempts_key) is None


def test_create_otp_session_resets_stale_attempts_counter(fake_redis):
    import asyncio

    attempts_key = OTPService._attempts_key("login", "tok")
    fake_redis.setex(attempts_key, 60, str(MAX_OTP_ATTEMPTS))

    asyncio.run(OTPService.create_otp_session(action="login", identifier="uid", token="tok", email="a@a.com"))

    assert fake_redis.get(attempts_key) is None


def test_verify_otp_sets_identifier_lockout_on_reaching_max_attempts(fake_redis):
    key = OTPService._key("register", "tok-1")
    fake_redis.setex(key, OTP_TTL_SECONDS, "123456")

    for _ in range(MAX_OTP_ATTEMPTS):
        OTPService.verify_otp("register", "tok-1", "wrong-guess", identifier="victim@example.com")

    lockout_key = OTPService._lockout_key("register", "victim@example.com")
    assert fake_redis.get(lockout_key) is not None
    assert fake_redis.ttl(lockout_key) > 0


def test_verify_otp_without_identifier_does_not_set_lockout(fake_redis):
    key = OTPService._key("register", "tok-1")
    fake_redis.setex(key, OTP_TTL_SECONDS, "123456")

    for _ in range(MAX_OTP_ATTEMPTS):
        OTPService.verify_otp("register", "tok-1", "wrong-guess")

    assert all(not k.startswith("otp_lockout:") for k in fake_redis.store)


def test_create_otp_session_refuses_fresh_code_while_identifier_locked_out(fake_redis):
    import asyncio

    email = "victim@example.com"
    key_a = OTPService._key("register", "tok-a")
    fake_redis.setex(key_a, OTP_TTL_SECONDS, "111111")

    for _ in range(MAX_OTP_ATTEMPTS):
        OTPService.verify_otp("register", "tok-a", "wrong-guess", identifier=email)

    lockout_key = OTPService._lockout_key("register", email)
    assert fake_redis.get(lockout_key) is not None

    response = asyncio.run(
        OTPService.create_otp_session(action="register", identifier=email, token="tok-b", email=email)
    )

    assert response["success"] is False
    assert response["status"] == "OTP_LOCKED"
    assert response["data"]["locked_seconds_remaining"] > 0

    key_b = OTPService._key("register", "tok-b")
    assert fake_redis.get(key_b) is None


def test_create_otp_session_succeeds_normally_once_lockout_naturally_expires(fake_redis):
    import asyncio

    email = "victim@example.com"
    lockout_key = OTPService._lockout_key("register", email)
    fake_redis.setex(lockout_key, 60, "1")
    fake_redis.delete(lockout_key)

    response = asyncio.run(
        OTPService.create_otp_session(action="register", identifier=email, token="tok-fresh", email=email)
    )

    assert response["success"] is True
    assert response["status"] == "OTP_SENT"
    key = OTPService._key("register", "tok-fresh")
    assert fake_redis.get(key) is not None
