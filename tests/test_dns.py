from reconmap.collectors.dns import (
    get_a_records,
    get_aaaa_records,
    get_ns_records,
)


def test_get_a_records():
    records = get_a_records("example.com")

    assert isinstance(records, list)
    assert len(records) > 0

    for record in records:
        assert isinstance(record, str)


def test_get_aaaa_records():
    records = get_aaaa_records("example.com")

    assert isinstance(records, list)

    for record in records:
        assert isinstance(record, str)


def test_get_ns_records():
    records = get_ns_records("example.com")

    assert isinstance(records, list)

    for record in records:
        assert isinstance(record, str)