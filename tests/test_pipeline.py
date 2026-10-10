from reconmap.core import pipeline


def test_passive_only_skips_http(monkeypatch):
    """Passive-only mode should not perform HTTP scanning."""

    def fake_a_records(domain):
        return ["93.184.216.34"]

    def fake_aaaa_records(domain):
        return []

    def fake_ns_records(domain):
        return []

    def fake_mx_records(domain):
        return []

    def fake_txt_records(domain):
        return []

    def fake_cname_records(domain):
        return []

    def fake_certificate_subdomains(domain):
        return []

    def fake_http_service(hostname):
        raise AssertionError(
            "HTTP scanning should not run in passive-only mode"
        )

    monkeypatch.setattr(
        pipeline,
        "get_a_records",
        fake_a_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_aaaa_records",
        fake_aaaa_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_ns_records",
        fake_ns_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_mx_records",
        fake_mx_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_txt_records",
        fake_txt_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_cname_records",
        fake_cname_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_certificate_subdomains",
        fake_certificate_subdomains,
    )

    monkeypatch.setattr(
        pipeline,
        "check_http_service",
        fake_http_service,
    )

    assets = pipeline.run_recon(
        "example.com",
        passive_only=True,
    )

    assert len(assets) == 1
    assert assets[0].hostname == "example.com"
    assert assets[0].ipv4 == ["93.184.216.34"]
    assert assets[0].http_services == []

def test_normal_mode_runs_http(monkeypatch):
    """Normal mode should perform HTTP scanning."""

    def fake_a_records(domain):
        return ["93.184.216.34"]

    def fake_aaaa_records(domain):
        return []

    def fake_ns_records(domain):
        return []

    def fake_mx_records(domain):
        return []

    def fake_txt_records(domain):
        return []

    def fake_cname_records(domain):
        return []

    def fake_certificate_subdomains(domain):
        return []

    def fake_http_service(hostname):
        return [
            {
                "scheme": "https",
                "url": f"https://{hostname}",
                "final_url": f"https://{hostname}/",
                "status_code": 200,
                "response_time": 0.25,
                "server": "test-server",
            }
        ]

    monkeypatch.setattr(
        pipeline,
        "get_a_records",
        fake_a_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_aaaa_records",
        fake_aaaa_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_ns_records",
        fake_ns_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_mx_records",
        fake_mx_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_txt_records",
        fake_txt_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_cname_records",
        fake_cname_records,
    )

    monkeypatch.setattr(
        pipeline,
        "get_certificate_subdomains",
        fake_certificate_subdomains,
    )

    monkeypatch.setattr(
        pipeline,
        "check_http_service",
        fake_http_service,
    )

    assets = pipeline.run_recon(
        "example.com",
        passive_only=False,
    )

    assert len(assets) == 1
    assert assets[0].hostname == "example.com"
    assert len(assets[0].http_services) == 1
    assert assets[0].http_services[0].scheme == "https"
    assert assets[0].http_services[0].status_code == 200    
    