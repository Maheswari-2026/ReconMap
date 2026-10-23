
import os
import secrets
import shutil
import threading
import time
from dataclasses import asdict
from pathlib import Path

from flask import (
    Flask,
    abort,
    make_response,
    render_template,
    request,
    send_from_directory,
    session,
)
from flask_wtf.csrf import CSRFProtect

from reconmap.analyzers.attack_surface import analyze_assets
from reconmap.core.pipeline import run_recon
from reconmap.output.csv_report import write_csv_report
from reconmap.output.json_report import write_json_report
from reconmap.utils.validators import normalize_domain, validate_domain


app = Flask(__name__)

app.config["SECRET_KEY"] = (
    os.environ.get("RECONMAP_SECRET_KEY") or secrets.token_hex(32)
)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("RECONMAP_HTTPS", "").lower() == "true"
)

# Allow HTTPS requests when the browser omits the Referer header.
app.config["WTF_CSRF_SSL_STRICT"] = False

csrf = CSRFProtect(app)

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"

RATE_WINDOW_SECONDS = 600
MAX_SCANS_PER_WINDOW = 5

scan_attempts = {}
scan_lock = threading.Lock()
rate_lock = threading.Lock()


def rate_limit_exceeded(client_ip: str) -> bool:
    """Limit scan submissions per client IP."""

    now = time.monotonic()
    cutoff = now - RATE_WINDOW_SECONDS

    with rate_lock:
        attempts = [
            timestamp
            for timestamp in scan_attempts.get(client_ip, [])
            if timestamp > cutoff
        ]

        if len(attempts) >= MAX_SCANS_PER_WINDOW:
            scan_attempts[client_ip] = attempts
            return True

        attempts.append(now)
        scan_attempts[client_ip] = attempts
        return False


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


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
            error = (
                "Confirm that you are authorized to assess this domain."
            )

        elif not validate_domain(domain):
            error = "Enter a valid domain, such as example.com."

        elif rate_limit_exceeded(request.remote_addr or "unknown"):
            error = (
                "Scan limit reached. Please wait ten minutes "
                "before submitting more scans."
            )

        elif not scan_lock.acquire(blocking=False):
            error = "Another scan is running. Please try again shortly."

        else:
            try:
                assets = run_recon(
                    domain,
                    passive_only=passive_only,
                )
                findings = analyze_assets(assets)

                # Create the results root folder if it does not exist.
                RESULTS_DIR.mkdir(parents=True, exist_ok=True)

                # Give every scan a separate, unpredictable ID.
                scan_id = secrets.token_urlsafe(24)
                report_dir = RESULTS_DIR / scan_id
                report_dir.mkdir(parents=True, exist_ok=False)

                json_path = report_dir / "report.json"
                csv_path = report_dir / "report.csv"

                write_json_report(
                    target=domain,
                    assets=assets,
                    findings=findings,
                    output_path=str(json_path),
                )

                write_csv_report(
                    assets=assets,
                    output_path=str(csv_path),
                )

                # Keep only the most recent 20 scan IDs in this session.
                allowed_reports = session.get("allowed_reports", [])
                if not isinstance(allowed_reports, list):
                    allowed_reports = []

                allowed_reports.append(scan_id)
                session["allowed_reports"] = allowed_reports[-20:]

                results = {
                    "target": domain,
                    "scan_id": scan_id,
                    "passive_only": passive_only,
                    "assets": [
                        asdict(asset) for asset in assets
                    ],
                    "findings": [
                        asdict(item) for item in findings
                    ],
                    "asset_count": len(assets),
                    "finding_count": len(findings),
                    "http_count": sum(
                        len(asset.http_services) for asset in assets
                    ),
                }
            except Exception:
                app.logger.exception("ReconMap scan failed")

                # Remove any incomplete report directory created by this scan.
                if "report_dir" in locals() and report_dir.exists():
                    try:
                        shutil.rmtree(report_dir)
                    except OSError:
                        app.logger.exception(
                            "Could not remove incomplete report directory"
                        )

                error = (
                    "The scan could not be completed. "
                    "Check the application terminal for details."
                )

            finally:
                scan_lock.release()

    response = make_response(
        render_template(
            "index.html",
            results=results,
            error=error,
            domain=domain,
            passive_only=passive_only,
        )
    )
    return response


@app.route("/download/<report_type>/<scan_id>")
def download_report(report_type, scan_id):
    """Download a report associated with a scan in this session."""

    if report_type not in {"json", "csv"}:
        abort(404)

    # Reject unexpected characters before constructing the path.
    if (
        not scan_id
        or not scan_id.isascii()
        or not scan_id.replace("-", "").replace("_", "").isalnum()
    ):
        abort(404)

    allowed_reports = session.get("allowed_reports", [])
    if not isinstance(allowed_reports, list):
        abort(403)

    if scan_id not in allowed_reports:
        abort(403)

    report_dir = RESULTS_DIR / scan_id
    filename = f"report.{report_type}"
    file_path = report_dir / filename

    if not file_path.is_file():
        abort(404, description="Report not found. Run a scan first.")

    return send_from_directory(
        str(report_dir),
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
