import argparse

from reconmap.collectors.dns import (
    get_a_records,
    get_aaaa_records,
    get_ns_records,
    get_mx_records,
)
from reconmap.utils.validators import normalize_domain, validate_domain


def main():
    parser = argparse.ArgumentParser(
        description="Automated information gathering and attack-surface enumeration tool"
    )

    parser.add_argument(
        "domain",
        help="Target domain"
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
    print("DNS RECONNAISSANCE")
    print("=" * 50)

    print(f"Domain: {domain}")

    # IPv4
    a_records = get_a_records(domain)

    print(f"A Records Found: {len(a_records)}")

    if a_records:
        for address in a_records:
            print(f"  - {address}")
    else:
        print("  - None found")

    # IPv6
    aaaa_records = get_aaaa_records(domain)

    print()
    print(f"AAAA Records Found: {len(aaaa_records)}")

    if aaaa_records:
        for address in aaaa_records:
            print(f"  - {address}")
    else:
        print("  - None found")

    # Name servers
    ns_records = get_ns_records(domain)

    print()
    print(f"NS Records Found: {len(ns_records)}")

    if ns_records:
        for server in ns_records:
            print(f"  - {server}")
    else:
        print("  - None found")
    #mx servers
    mx_records = get_mx_records(domain)

    print()
    print(f"MX Records Found: {len(mx_records)}")

    if mx_records:
        for record in mx_records:
            print(
                f"  - Priority: {record['priority']} "
                f"Server: {record['server']}"
            )
    else:
        print("  - None found")    