import csv
from pathlib import Path

from reconmap.core.models import Asset


def write_csv_report(
    assets: list[Asset],
    output_path: str,
) -> None:
    """Write reconnaissance assets to a CSV file."""

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "hostname",
                "ipv4",
                "ipv6",
                "nameservers",
                "mail_servers",
                "txt_records",
                "cname_records",
                "certificate_sources",
                "http_services",
            ],
        )

        writer.writeheader()

        for asset in assets:

            ipv4 = "; ".join(asset.ipv4)
            ipv6 = "; ".join(asset.ipv6)
            nameservers = "; ".join(asset.nameservers)
            txt_records = "; ".join(asset.txt_records)
            cname_records = "; ".join(asset.cname_records)
            certificate_sources = "; ".join(
                asset.certificate_sources
            )

            mail_servers = "; ".join(
                f"{server['priority']}:{server['server']}"
                for server in asset.mail_servers
            )

            http_services = "; ".join(
                (
                    f"{service.scheme.upper()} "
                    f"{service.status_code} "
                    f"{service.final_url}"
                )
                for service in asset.http_services
            )

            writer.writerow(
                {
                    "hostname": asset.hostname,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "nameservers": nameservers,
                    "mail_servers": mail_servers,
                    "txt_records": txt_records,
                    "cname_records": cname_records,
                    "certificate_sources": certificate_sources,
                    "http_services": http_services,
                }
            )