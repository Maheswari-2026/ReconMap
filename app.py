
from dataclasses import asdict
from pathlib import Path

from flask import (
    Flask,
    abort,
    render_template,
    request,
    send_from_directory,
)

from reconmap.analyzers.attack_surface import analyze_assets
from reconmap.core.pipeline import run_recon
from reconmap.output.csv_report import write_csv_report
from reconmap.output.json_report import write_json_report
from reconmap.utils.validators import normalize_domain, validate_domain


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None
    domain = ""
    passive_only = True

    if request.method == "POST":
        domain = normalize_domain(request.form.get("domain", ""))
        passive_only = request.form.get("mode") == "passive"
        authorized = request.form.get("authorized") == "yes"

        if not authorized:
            error = "Confirm that you are authorized to assess this domain."

        elif not validate_domain(domain):
            error = "Enter a valid domain, such as example.com."

        else:
            try:
                assets = run_recon(
                    domain,
                    passive_only=passive_only,
                )
                findings = analyze_assets(assets)

                RESULTS_DIR.mkdir(parents=True, exist_ok=True)

                write_json_report(
                    target=domain,
                    assets=assets,
                    findings=findings,
                    output_path=str(
                        RESULTS_DIR / f"{domain}-report.json"
                    ),
                )

                write_csv_report(
                    assets=assets,
                    output_path=str(
                        RESULTS_DIR / f"{domain}-report.csv"
                    ),
                )

                results = {
                    "target": domain,
                    "passive_only": passive_only,
                    "assets": [asdict(asset) for asset in assets],
                    "findings": [asdict(item) for item in findings],
                    "asset_count": len(assets),
                    "finding_count": len(findings),
                    "http_count": sum(
                        len(asset.http_services) for asset in assets
                    ),
                }

            except Exception:
                app.logger.exception("ReconMap scan failed")
                error = (
                    "The scan could not be completed. "
                    "Check the application terminal for details."
                )

    return render_template(
        "index.html",
        results=results,
        error=error,
        domain=domain,
        passive_only=passive_only,
    )


@app.route("/download/<report_type>/<domain>")
def download_report(report_type, domain):
    """Download a report for a validated domain."""

    if report_type not in {"json", "csv"}:
        abort(404)

    domain = normalize_domain(domain)

    if not validate_domain(domain):
        abort(404)

    filename = f"{domain}-report.{report_type}"
    file_path = RESULTS_DIR / filename

    if not file_path.is_file():
        abort(404, description="Report not found. Run a scan first.")

    return send_from_directory(
        str(RESULTS_DIR),
        filename,
        as_attachment=True,
        download_name=filename,
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
