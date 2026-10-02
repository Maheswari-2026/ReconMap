import httpx


CRT_SH_URL = "https://crt.sh/"


def get_certificate_subdomains(domain: str) -> list[str]:
    """Return unique subdomains discovered from Certificate Transparency logs."""

    params = {
        "q": f"%.{domain}",
        "output": "json",
    }

    try:
        response = httpx.get(
            CRT_SH_URL,
            params=params,
            timeout=10.0,
        )

        response.raise_for_status()

        certificates = response.json()

        subdomains = set()

        for certificate in certificates:
            name_value = certificate.get("name_value", "")

            for name in name_value.splitlines():
                name = name.strip().lower()

                if name.startswith("*."):
                    name = name[2:]

                if name == domain or name.endswith(f".{domain}"):
                    subdomains.add(name)

        return sorted(subdomains)

    except (httpx.HTTPError, ValueError):
        return []