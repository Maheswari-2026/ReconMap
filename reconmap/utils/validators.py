import re


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def normalize_domain(domain: str) -> str:
    """Normalize a user-provided domain."""
    domain = domain.strip().lower()

    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]

    domain = domain.rstrip("/")

    return domain


def validate_domain(domain: str) -> bool:
    """Return True when the domain has a valid hostname format."""
    return bool(DOMAIN_PATTERN.fullmatch(domain))