
import httpx


CRT_SH_URL = "https://crt.sh/"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB


def get_certificate_subdomains(domain: str) -> list[str]:
    """Return unique subdomains discovered from Certificate Transparency logs."""

    params = {
        "q": f"%.{domain}",
        "output": "json",
    }

    try:
        with httpx.stream(
            "GET",
            CRT_SH_URL,
            params=params,
            timeout=10.0,
            follow_redirects=False,
            trust_env=False,
        ) as response:
            response.raise_for_status()

            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > MAX_RESPONSE_BYTES:
                        return []
                except ValueError:
                    pass

            chunks = []
            total_bytes = 0

            for chunk in response.iter_bytes():
                total_bytes += len(chunk)

                if total_bytes > MAX_RESPONSE_BYTES:
                    return []

                chunks.append(chunk)

            certificates = httpx.Response(
                status_code=response.status_code,
                content=b"".join(chunks),
            ).json()

        if not isinstance(certificates, list):
            return []

        subdomains = set()

        for certificate in certificates:
            if not isinstance(certificate, dict):
                continue

            name_value = certificate.get("name_value", "")
            if not isinstance(name_value, str):
                continue

            for name in name_value.splitlines():
                name = name.strip().lower()

                if name.startswith("*."):
                    name = name[2:]

                if name == domain or name.endswith(f".{domain}"):
                    subdomains.add(name)

        return sorted(subdomains)

    except (httpx.HTTPError, ValueError):
        return []
