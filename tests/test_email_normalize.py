from utils.email_normalize import normalize_email


def test_normalize_email_strips_plus_tag():
    assert normalize_email("a+1@a.com") == "a@a.com"


def test_normalize_email_lowercases():
    assert normalize_email("A+Tag@Example.COM") == "a@example.com"


def test_normalize_email_no_plus_unchanged_besides_case():
    assert normalize_email("User@Example.com") == "user@example.com"


def test_normalize_email_strips_surrounding_whitespace():
    assert normalize_email("  a+1@a.com  ") == "a@a.com"


def test_normalize_email_multiple_plus_signs_strips_from_first():
    assert normalize_email("a+1+2@a.com") == "a@a.com"


def test_normalize_email_no_at_sign_returns_lowercased():
    assert normalize_email("NotAnEmail") == "notanemail"
