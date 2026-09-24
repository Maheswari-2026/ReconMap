from reconmap.collectors.dns import get_a_records


def test_get_a_records():
    records = get_a_records("example.com")

    assert isinstance(records, list)
    assert len(records) > 0

    for record in records:
        assert isinstance(record, str)