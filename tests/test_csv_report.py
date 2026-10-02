from reconmap.core.models import Asset, HTTPService
from reconmap.output.csv_report import write_csv_report


def test_write_csv_report(tmp_path):

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
        ipv6=["2606:2800:220:1:248:1893:25c8:1946"],
        nameservers=[
            "ns1.example.com",
            "ns2.example.com",
        ],
        mail_servers=[
            {
                "priority": 10,
                "server": "mail.example.com",
            }
        ],
        txt_records=[
            "v=spf1 -all",
        ],
        cname_records=[],
        certificate_sources=[
            "certificate_transparency",
        ],
        http_services=[
            service,
        ],
    )

    output_file = tmp_path / "report.csv"

    write_csv_report(
        assets=[asset],
        output_path=str(output_file),
    )

    assert output_file.exists()

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "hostname" in content
    assert "example.com" in content
    assert "93.184.216.34" in content
    assert "certificate_transparency" in content
    assert "HTTPS 200" in content