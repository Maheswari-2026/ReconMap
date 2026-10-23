
import ipaddress
import socket
import time
from urllib.parse import urljoin, urlparse

import httpx


REQUEST_TIMEOUT = 5.0
MAX_REDIRECTS = 3


def _has_public_addresses(hostname: str) -> bool:
    """Return True only when DNS resolves exclusively to public IPs."""

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError):
        return False

    if not addresses:
        return False

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError:
            return False

        if not ip.is_global:
            return False

    return True


def _safe_url(url: str) -> bool:
    """Allow only HTTP(S) URLs pointing to public DNS destinations."""

    try:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        if not parsed.hostname or parsed.username or parsed.password:
            return False

        if parsed.port not in {None, 80, 443}:
            return False

        return _has_public_addresses(parsed.hostname)

    except (ValueError, UnicodeError):
        return False


def check_http_service(hostname: str) -> list[dict]:
    """Check public HTTP(S) services without automatically following redirects."""

    results = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        current_url = url
        started = time.monotonic()

        try:
            for _ in range(MAX_REDIRECTS + 1):
                if not _safe_url(current_url):
                    break

                with httpx.Client(
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = client.get(
                        current_url,
                        headers={"User-Agent": "ReconMap/1.0"},
                    )

                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        break

                    next_url = urljoin(current_url, location)

                    # Validate the next destination before making another request.
                    if not _safe_url(next_url):
                        break

                    current_url = next_url
                    continue

                results.append(
                    {
                        "scheme": scheme,
                        "url": url,
                        "final_url": str(response.url),
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "server": response.headers.get("server", ""),
                    }
                )
                break

        except (httpx.HTTPError, OSError, ValueError):
            continue

    return results
