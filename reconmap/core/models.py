from dataclasses import dataclass, field


@dataclass
class HTTPService:
    """Represent an HTTP or HTTPS service discovered on an asset."""

    scheme: str
    url: str
    final_url: str
    status_code: int
    response_time: float
    server: str = ""


@dataclass
class Asset:
    """Represent a discovered hostname and its reconnaissance data."""

    hostname: str

    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)

    nameservers: list[str] = field(default_factory=list)
    mail_servers: list[dict] = field(default_factory=list)

    txt_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)

    certificate_sources: list[str] = field(default_factory=list)

    http_services: list[HTTPService] = field(default_factory=list)