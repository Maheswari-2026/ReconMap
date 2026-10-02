from dataclasses import dataclass, field

from reconmap.core.models import Asset


@dataclass
class AttackSurfaceFinding:
    """Represent an observable attack-surface finding."""

    hostname: str
    finding_type: str
    description: str
    details: dict = field(default_factory=dict)


def analyze_asset(asset: Asset) -> list[AttackSurfaceFinding]:
    """Analyze an asset and return observable exposure findings."""

    findings = []

    # Web service exposure
    if asset.http_services:
        findings.append(
            AttackSurfaceFinding(
                hostname=asset.hostname,
                finding_type="web_service",
                description="A web service was detected on this hostname.",
                details={
                    "services": len(asset.http_services),
                },
            )
        )

    # HTTPS availability
    https_services = [
        service
        for service in asset.http_services
        if service.scheme == "https"
    ]

    if https_services:
        findings.append(
            AttackSurfaceFinding(
                hostname=asset.hostname,
                finding_type="https_available",
                description="HTTPS is available on this hostname.",
                details={
                    "services": len(https_services),
                },
            )
        )

    # HTTP availability
    http_services = [
        service
        for service in asset.http_services
        if service.scheme == "http"
    ]

    if http_services:
        findings.append(
            AttackSurfaceFinding(
                hostname=asset.hostname,
                finding_type="http_available",
                description="HTTP is available on this hostname.",
                details={
                    "services": len(http_services),
                },
            )
        )

    # Certificate discovery
    if asset.certificate_sources:
        findings.append(
            AttackSurfaceFinding(
                hostname=asset.hostname,
                finding_type="certificate_discovery",
                description=(
                    "This hostname was discovered through "
                    "Certificate Transparency data."
                ),
                details={
                    "sources": asset.certificate_sources,
                },
            )
        )

    # DNS information
    if asset.ipv4 or asset.ipv6:
        findings.append(
            AttackSurfaceFinding(
                hostname=asset.hostname,
                finding_type="dns_resolution",
                description="The hostname resolves to one or more IP addresses.",
                details={
                    "ipv4_count": len(asset.ipv4),
                    "ipv6_count": len(asset.ipv6),
                },
            )
        )

    return findings


def analyze_assets(
    assets: list[Asset],
) -> list[AttackSurfaceFinding]:
    """Analyze all discovered assets."""

    findings = []

    for asset in assets:
        findings.extend(analyze_asset(asset))

    return findings