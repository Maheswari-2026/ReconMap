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


def get_ns_records(domain: str) -> list[str]:
    """Return authoritative name servers for a domain."""

    try:
        answers = dns.resolver.resolve(domain, "NS")

        return [answer.target.to_text().rstrip(".") for answer in answers]

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.Timeout:
        return []
    
    
def get_mx_records(domain: str) -> list[dict]:
    """Return mail exchange servers and their priorities for a domain."""

    try:
        answers = dns.resolver.resolve(domain, "MX")

        records = []

        for answer in answers:
            server = answer.exchange.to_text().rstrip(".")

            if server == "":
                server = "No mail service"

            records.append(
                {
                    "priority": answer.preference,
                    "server": server,
                }
            )

        return records

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.Timeout:
        return []
     
    
def get_txt_records(domain: str) -> list[str]:
    """Return TXT records for a domain."""

    try:
        answers = dns.resolver.resolve(domain, "TXT")

        return [
            "".join(part.decode("utf-8") for part in answer.strings)
            for answer in answers
        ]

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.Timeout:
        return []   
    
def get_cname_records(domain: str) -> list[str]:
    """Return canonical name records for a domain."""

    try:
        answers = dns.resolver.resolve(domain, "CNAME")

        return [
            answer.target.to_text().rstrip(".")
            for answer in answers
        ]

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.Timeout:
        return []       