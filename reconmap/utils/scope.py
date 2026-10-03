def is_in_scope(hostname: str, target_domain: str) -> bool:
    """Return True when a hostname belongs to the target domain."""

    hostname = hostname.strip().lower().rstrip(".")
    target_domain = target_domain.strip().lower().rstrip(".")

    if hostname == target_domain:
        return True

    return hostname.endswith(f".{target_domain}")