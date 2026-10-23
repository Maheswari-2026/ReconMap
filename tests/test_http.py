
import httpx

from reconmap.scanners.http import check_http_service


def test_check_http_service(monkeypatch):
    """Test HTTP discovery without making real network requests."""

    class MockElapsed:
        def total_seconds(self):
            return 0.25

    class MockResponse:
        def __init__(self, url, status_code=200, server="test-server"):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.elapsed = MockElapsed()
            self.headers = {"server": server}

        @property
        def is_redirect(self):
            return self.status_code in {301, 302, 303, 307, 308}

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, headers=None):
            if str(url).startswith("https://"):
                return MockResponse("https://example.com/")

            return MockResponse("http://example.com/")

    monkeypatch.setattr(
        "reconmap.scanners.http._safe_url",
        lambda url: True,
    )
    monkeypatch.setattr(
        "reconmap.scanners.http.httpx.Client",
        MockClient,
    )

    results = check_http_service("example.com")

    assert len(results) == 2
    assert results[0]["scheme"] == "https"
    assert results[0]["status_code"] == 200
    assert results[0]["final_url"] == "https://example.com/"
    assert results[0]["response_time"] == 0.25
    assert results[0]["server"] == "test-server"

    assert results[1]["scheme"] == "http"
    assert results[1]["status_code"] == 200
    assert results[1]["final_url"] == "http://example.com/"
