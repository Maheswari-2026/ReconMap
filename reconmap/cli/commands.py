import argparse

from reconmap.core.pipeline import run_recon
from reconmap.utils.validators import normalize_domain, validate_domain
from reconmap.analyzers.attack_surface import analyze_assets
from reconmap.output.json_report import write_json_report
from reconmap.output.csv_report import write_csv_report


def main():
    parser = argparse.ArgumentParser(
        description="Automated information gathering and attack-surface enumeration tool"
    )

    parser.add_argument(
        "domain",
        help="Target domain",
    )
    
    parser.add_argument(
    "--passive-only",
    action="store_true",
    help="Perform passive reconnaissance only",
    )

    args = parser.parse_args()

    domain = normalize_domain(args.domain)

    if not validate_domain(domain):
        parser.error(f"Invalid domain: {args.domain}")

    print("ReconMap")
    print(f"Target: {domain}")
    print("Starting reconnaissance...")

    print()
    print("=" * 50)
    print("RECONNAISSANCE")
    print("=" * 50)

    assets = run_recon(
    domain,
    passive_only=args.passive_only,
    )
    
    findings = analyze_assets(assets)
    
    write_json_report(
    target=domain,
    assets=assets,
    findings=findings,
    output_path=f"results/{domain}-report.json",
    )
    
    write_csv_report(
    assets=assets,
    output_path=f"results/{domain}-report.csv",
    )
    
    print()
    print(f"Assets Discovered: {len(assets)}")

    for asset in assets:
        print()
        print("-" * 50)
        print(f"Hostname: {asset.hostname}")

        print(f"IPv4: {len(asset.ipv4)}")
        for address in asset.ipv4:
            print(f"  - {address}")

        print(f"IPv6: {len(asset.ipv6)}")
        for address in asset.ipv6:
            print(f"  - {address}")

        print(f"Name Servers: {len(asset.nameservers)}")
        for server in asset.nameservers:
            print(f"  - {server}")

        print(f"Mail Servers: {len(asset.mail_servers)}")
        for server in asset.mail_servers:
            print(
                f"  - Priority: {server['priority']} "
                f"Server: {server['server']}"
            )

        print(f"TXT Records: {len(asset.txt_records)}")
        for record in asset.txt_records:
            print(f"  - {record}")

        print(f"CNAME Records: {len(asset.cname_records)}")
        for record in asset.cname_records:
            print(f"  - {record}")

        print(
            f"Certificate Sources: "
            f"{len(asset.certificate_sources)}"
        )

        for source in asset.certificate_sources:
            print(f"  - {source}")

        print(f"HTTP Services: {len(asset.http_services)}")

        for service in asset.http_services:
            print(
                f"  - {service.scheme.upper()} "
                f"{service.status_code} "
                f"{service.final_url}"
            )

    print()
    print("=" * 50)
    print("RECONNAISSANCE COMPLETE")
    print("=" * 50)