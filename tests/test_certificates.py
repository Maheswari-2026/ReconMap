import httpx

from reconmap.collectors.certificates import get_certificate_subdomains


def test_get_certificate_subdomains(monkeypatch):
    """Test CT discovery without making a real network request."""

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return [
                {
                    "name_value": (
                        "example.com\n"
                        "www.example.com\n"
                        "*.api.example.com\n"
                    )
                },
                {
                    "name_value": "mail.example.com"
                },
            ]

    def fake_get(
        url,
        params,
        timeout,
    ):
        assert url == "https://crt.sh/"
        assert params["q"] == "%.example.com"
        assert params["output"] == "json"
        assert timeout == 10.0

        return MockResponse()

    monkeypatch.setattr(
        httpx,
        "get",
        fake_get,
    )

    results = get_certificate_subdomains(
        "example.com"
    )

    assert results == [
        "api.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]