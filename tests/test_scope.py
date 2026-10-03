from reconmap.utils.scope import is_in_scope


def test_target_domain_is_in_scope():
    assert is_in_scope(
        "example.com",
        "example.com",
    ) is True


def test_subdomain_is_in_scope():
    assert is_in_scope(
        "api.example.com",
        "example.com",
    ) is True


def test_deep_subdomain_is_in_scope():
    assert is_in_scope(
        "dev.api.example.com",
        "example.com",
    ) is True


def test_different_domain_is_out_of_scope():
    assert is_in_scope(
        "example.org",
        "example.com",
    ) is False


def test_similar_domain_is_out_of_scope():
    assert is_in_scope(
        "evil-example.com",
        "example.com",
    ) is False


def test_nested_external_domain_is_out_of_scope():
    assert is_in_scope(
        "example.com.evil.com",
        "example.com",
    ) is False


def test_case_insensitive():
    assert is_in_scope(
        "API.Example.COM",
        "EXAMPLE.COM",
    ) is True


def test_trailing_dot():
    assert is_in_scope(
        "api.example.com.",
        "example.com.",
    ) is True