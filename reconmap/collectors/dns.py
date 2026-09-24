import dns.resolver


def get_a_records(domain: str) -> list[str]:
    """Return IPv4 addresses for a domain."""

    try:
        answers = dns.resolver.resolve(domain, "A")

        return [answer.address for answer in answers]

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.Timeout:
        return []


def get_aaaa_records(domain: str) -> list[str]:
    """Return IPv6 addresses for a domain."""

    try:
        answers = dns.resolver.resolve(domain, "AAAA")

        return [answer.address for answer in answers]

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.Timeout:
        return []