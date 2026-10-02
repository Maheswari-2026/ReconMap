from reconmap.collectors.certificates import get_certificate_subdomains
from reconmap.collectors.dns import (
    get_a_records,
    get_aaaa_records,
    get_cname_records,
    get_mx_records,
    get_ns_records,
    get_txt_records,
)
from reconmap.core.models import Asset, HTTPService
from reconmap.scanners.http import check_http_service


def run_recon(domain: str) -> list[Asset]:
    """Run reconnaissance and return discovered assets."""

    assets = {}

    # -------------------------
    # Target domain DNS
    # -------------------------

    target_asset = Asset(hostname=domain)

    target_asset.ipv4 = get_a_records(domain)
    target_asset.ipv6 = get_aaaa_records(domain)
    target_asset.nameservers = get_ns_records(domain)
    target_asset.mail_servers = get_mx_records(domain)
    target_asset.txt_records = get_txt_records(domain)
    target_asset.cname_records = get_cname_records(domain)

    target_asset.certificate_sources.append(
        "certificate_transparency"
    )

    assets[domain] = target_asset

    # -------------------------
    # Certificate Transparency
    # -------------------------

    subdomains = get_certificate_subdomains(domain)

    for subdomain in subdomains:

        if subdomain not in assets:
            assets[subdomain] = Asset(
                hostname=subdomain,
                certificate_sources=[
                    "certificate_transparency"
                ],
            )

    # -------------------------
    # HTTP discovery
    # -------------------------

    for asset in assets.values():

        http_results = check_http_service(asset.hostname)

        asset.http_services = [
            HTTPService(
                scheme=result["scheme"],
                url=result["url"],
                final_url=result["final_url"],
                status_code=result["status_code"],
                response_time=result["response_time"],
                server=result["server"],
            )
            for result in http_results
        ]

    return list(assets.values())