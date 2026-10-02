import httpx


def check_http_service(hostname: str) -> list[dict]:
    """Check whether HTTP or HTTPS is available for a hostname."""

    results = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"

        try:
            response = httpx.get(
                url,
                timeout=5.0,
                follow_redirects=True,
            )

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

        except httpx.HTTPError:
            continue

    return results