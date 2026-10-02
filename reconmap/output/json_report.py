import json
from dataclasses import asdict
from pathlib import Path

from reconmap.analyzers.attack_surface import AttackSurfaceFinding
from reconmap.core.models import Asset


def write_json_report(
    target: str,
    assets: list[Asset],
    findings: list[AttackSurfaceFinding],
    output_path: str,
) -> None:
    """Write reconnaissance results to a JSON file."""

    report = {
        "target": target,
        "assets": [
            asdict(asset)
            for asset in assets
        ],
        "attack_surface": [
            asdict(finding)
            for finding in findings
        ],
    }

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )