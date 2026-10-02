import json

from reconmap.analyzers.attack_surface import AttackSurfaceFinding
from reconmap.core.models import Asset
from reconmap.output.json_report import write_json_report


def test_write_json_report(tmp_path):

    asset = Asset(
        hostname="example.com",
        ipv4=["93.184.216.34"],
    )

    finding = AttackSurfaceFinding(
        hostname="example.com",
        finding_type="dns_resolution",
        description="The hostname resolves to one or more IP addresses.",
        details={
            "ipv4_count": 1,
            "ipv6_count": 0,
        },
    )

    output_file = tmp_path / "report.json"

    write_json_report(
        target="example.com",
        assets=[asset],
        findings=[finding],
        output_path=str(output_file),
    )

    assert output_file.exists()

    with output_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        report = json.load(file)

    assert report["target"] == "example.com"
    assert len(report["assets"]) == 1
    assert len(report["attack_surface"]) == 1