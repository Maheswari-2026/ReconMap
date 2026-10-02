from reconmap.scanners.http import check_http_service


def test_check_http_service():
    results = check_http_service("example.com")

    assert isinstance(results, list)

    for result in results:
        assert isinstance(result, dict)
        assert "scheme" in result
        assert "url" in result
        assert "final_url" in result
        assert "status_code" in result
        assert "response_time" in result
        assert "server" in result