
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
from reconmap.utils.scope import is_in_scope


MAX_ASSETS = 100


def run_recon(
    domain: str,
    passive_only: bool = False,
) -> list[Asset]:
    """Run reconnaissance on the requested domain and in-scope subdomains."""

    assets = {}

    target_asset = Asset(hostname=domain)
    target_asset.ipv4 = get_a_records(domain)
    target_asset.ipv6 = get_aaaa_records(domain)
    target_asset.nameservers = get_ns_records(domain)
    target_asset.mail_servers = get_mx_records(domain)
    target_asset.txt_records = get_txt_records(domain)
    target_asset.cname_records = get_cname_records(domain)
    target_asset.certificate_sources.append("certificate_transparency")

    assets[domain] = target_asset

    # Include only valid in-scope certificate names, up to the asset limit.
    subdomains = get_certificate_subdomains(domain)

    for subdomain in subdomains:
        hostname = subdomain.strip().lower().rstrip(".")

        if not is_in_scope(hostname, domain):
            continue

        if hostname not in assets and len(assets) < MAX_ASSETS:
            assets[hostname] = Asset(
                hostname=hostname,
                certificate_sources=["certificate_transparency"],
            )

        if len(assets) >= MAX_ASSETS:
            break

    if not passive_only:
        for asset in assets.values():
            if not is_in_scope(asset.hostname, domain):
                continue

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
