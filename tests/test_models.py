from reconmap.core.models import Asset, HTTPService


def test_http_service():
    service = HTTPService(
        scheme="https",
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        response_time=0.25,
        server="example-server",
    )

    assert service.scheme == "https"
    assert service.status_code == 200
    assert service.server == "example-server"


def test_asset():
    asset = Asset(
        hostname="example.com",
        ipv4=["93.184.216.34"],
    )

    assert asset.hostname == "example.com"
    assert asset.ipv4 == ["93.184.216.34"]
    assert asset.ipv6 == []
    assert asset.http_services == []