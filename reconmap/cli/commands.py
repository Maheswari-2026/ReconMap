import argparse

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