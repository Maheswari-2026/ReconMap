from reconmap.utils.validators import normalize_domain, validate_domain


def test_normalize_https_domain():
    assert normalize_domain("HTTPS://Example.COM/") == "example.com"


def test_normalize_http_domain():
    assert normalize_domain("http://Example.COM") == "example.com"


def test_valid_domain():
    assert validate_domain("example.com") is True


def test_invalid_domain():
    assert validate_domain("not a domain") is False