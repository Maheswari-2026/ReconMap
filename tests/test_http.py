import httpx

from reconmap.scanners.http import check_http_service


def test_check_http_service(monkeypatch):
    """Test HTTP discovery without making real network requests."""

    class MockElapsed:
        def total_seconds(self):
            return 0.25

    class MockResponse:
        def __init__(self, url, status_code, server):
            self.url = url
            self.status_code = status_code
            self.elapsed = MockElapsed()
            self.headers = {
                "server": server,
            }

    def fake_get(
        url,
        timeout,
        follow_redirects,
    ):
        if url.startswith("https://"):
            return MockResponse(
                url="https://example.com/",
                status_code=200,
                server="test-server",
            )

        return MockResponse(
            url="http://example.com/",
            status_code=200,
            server="test-server",
        )

    monkeypatch.setattr(
        httpx,
        "get",
        fake_get,
    )

    results = check_http_service(
        "example.com"
    )

    assert len(results) == 2

    assert results[0]["scheme"] == "https"
    assert results[0]["status_code"] == 200
    assert results[0]["final_url"] == "https://example.com/"
    assert results[0]["response_time"] == 0.25
    assert results[0]["server"] == "test-server"

    assert results[1]["scheme"] == "http"
    assert results[1]["status_code"] == 200
    assert results[1]["final_url"] == "http://example.com/"
    assert results[1]["response_time"] == 0.25
    assert results[1]["server"] == "test-server"