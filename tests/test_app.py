
import app as reconmap_app


def test_dashboard_opens():
    client = reconmap_app.app.test_client()

    response = client.get("/")

    assert response.status_code == 200


def test_download_rejects_invalid_report_type():
    client = reconmap_app.app.test_client()

    response = client.get("/download/pdf/invalidscanid")

    assert response.status_code == 404


def test_download_rejects_scan_not_in_session():
    client = reconmap_app.app.test_client()

    with client.session_transaction() as session:
        session["allowed_reports"] = []

    response = client.get(
        "/download/json/abcdefghijklmnop"
    )

    assert response.status_code == 403


def test_failed_scan_does_not_leave_report_directory(monkeypatch, tmp_path):
    reconmap_app.app.config["WTF_CSRF_ENABLED"] = False
    client = reconmap_app.app.test_client()

    monkeypatch.setattr(
        reconmap_app,
        "RESULTS_DIR",
        tmp_path,
    )

    monkeypatch.setattr(
        reconmap_app,
        "run_recon",
        lambda domain, passive_only=False: [],
    )

    def fail_json_report(**kwargs):
        raise RuntimeError("Simulated report failure")

    monkeypatch.setattr(
        reconmap_app,
        "write_json_report",
        fail_json_report,
    )

    response = client.post(
        "/",
        data={
            "domain": "example.com",
            "mode": "passive",
            "authorized": "yes",
        },
    )

    assert response.status_code == 200
    assert b"could not be completed" in response.data
    assert list(tmp_path.iterdir()) == []
