
import httpx

from reconmap.collectors.certificates import (
    MAX_RESPONSE_BYTES,
    get_certificate_subdomains,
)


def test_get_certificate_subdomains(monkeypatch):
    """Test CT discovery without making a real network request."""

    class MockResponse:
        status_code = 200
        headers = {"content-length": "100"}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def raise_for_status(self):
            pass

        def iter_bytes(self):
            yield (
                b'[{"name_value":"example.com\\n'
                b'www.example.com\\n'
                b'*.api.example.com\\n"},'
                b'{"name_value":"mail.example.com"}]'
            )

    def fake_stream(method, url, params, timeout, follow_redirects, trust_env):
        assert method == "GET"
        assert url == "https://crt.sh/"
        assert params["q"] == "%.example.com"
        assert params["output"] == "json"
        assert timeout == 10.0
        assert follow_redirects is False
        assert trust_env is False
        return MockResponse()

    monkeypatch.setattr(httpx, "stream", fake_stream)

    results = get_certificate_subdomains("example.com")

    assert results == [
        "api.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]


def test_get_certificate_subdomains_rejects_large_content_length(monkeypatch):
    """Reject a response that declares a size above the configured limit."""

    class MockResponse:
        status_code = 200
        headers = {"content-length": str(MAX_RESPONSE_BYTES + 1)}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def raise_for_status(self):
            pass

        def iter_bytes(self):
            raise AssertionError("Oversized response should not be read")

    def fake_stream(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(httpx, "stream", fake_stream)

    assert get_certificate_subdomains("example.com") == []


def test_get_certificate_subdomains_rejects_oversized_stream(monkeypatch):
    """Reject a response that exceeds the limit while streaming."""

    class MockResponse:
        status_code = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def raise_for_status(self):
            pass

        def iter_bytes(self):
            yield b"x" * (MAX_RESPONSE_BYTES + 1)

    def fake_stream(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(httpx, "stream", fake_stream)

    assert get_certificate_subdomains("example.com") == []
