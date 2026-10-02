from reconmap.analyzers.attack_surface import (
    analyze_asset,
    analyze_assets,
)
from reconmap.core.models import Asset, HTTPService


def test_analyze_asset_with_https():

    service = HTTPService(
        scheme="https",
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        response_time=0.25,
        server="example-server",
    )

    asset = Asset(
        hostname="example.com",
        ipv4=["93.184.216.34"],
        certificate_sources=["certificate_transparency"],
        http_services=[service],
    )

    findings = analyze_asset(asset)

    assert isinstance(findings, list)
    assert len(findings) > 0

    finding_types = [
        finding.finding_type
        for finding in findings
    ]

    assert "web_service" in finding_types
    assert "https_available" in finding_types
    assert "certificate_discovery" in finding_types
    assert "dns_resolution" in finding_types


def test_analyze_empty_asset():

    asset = Asset(
        hostname="unknown.example.com"
    )

    findings = analyze_asset(asset)

    assert isinstance(findings, list)
    assert findings == []


def test_analyze_assets():

    asset = Asset(
        hostname="example.com",
        ipv4=["93.184.216.34"],
    )

    findings = analyze_assets([asset])

    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0].finding_type == "dns_resolution"