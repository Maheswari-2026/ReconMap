from reconmap.collectors.certificates import get_certificate_subdomains


def test_get_certificate_subdomains():
    records = get_certificate_subdomains("example.com")

    assert isinstance(records, list)

    for record in records:
        assert isinstance(record, str)