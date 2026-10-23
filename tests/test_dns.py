import dns.resolver

from reconmap.collectors.dns import (
    get_a_records,
    get_aaaa_records,
    get_ns_records,
    get_mx_records,
    get_txt_records,
    get_cname_records,
)


class MockARecord:
    def __init__(self, address):
        self.address = address


class MockDNSName:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class MockNSRecord:
    def __init__(self, target):
        self.target = MockDNSName(target)


class MockMXRecord:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = MockDNSName(exchange)


class MockCNAMERecord:
    def __init__(self, target):
        self.target = MockDNSName(target)


class MockTXTRecord:
    def __init__(self, strings):
        self.strings = strings


def test_get_a_records(monkeypatch):
    """Test A record discovery without real DNS requests."""

    def fake_resolve(domain, record_type, **kwargs):
        assert domain == "example.com"
        assert record_type == "A"
        assert kwargs["lifetime"] == 5.0

        return [
            MockARecord("93.184.216.34"),
            MockARecord("93.184.216.35"),
        ]

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    results = get_a_records("example.com")

    assert results == [
        "93.184.216.34",
        "93.184.216.35",
    ]


def test_get_aaaa_records(monkeypatch):
    """Test AAAA record discovery without real DNS requests."""

    def fake_resolve(domain, record_type):
        assert domain == "example.com"
        assert record_type == "AAAA"

        return [
            MockARecord("2001:db8::1"),
            MockARecord("2001:db8::2"),
        ]

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    results = get_aaaa_records("example.com")

    assert results == [
        "2001:db8::1",
        "2001:db8::2",
    ]


def test_get_ns_records(monkeypatch):
    """Test NS record discovery without real DNS requests."""

    def fake_resolve(domain, record_type):
        assert domain == "example.com"
        assert record_type == "NS"

        return [
            MockNSRecord("ns1.example.com."),
            MockNSRecord("ns2.example.com."),
        ]

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    results = get_ns_records("example.com")

    assert results == [
        "ns1.example.com",
        "ns2.example.com",
    ]


def test_get_mx_records(monkeypatch):
    """Test MX record discovery without real DNS requests."""

    def fake_resolve(domain, record_type):
        assert domain == "example.com"
        assert record_type == "MX"

        return [
            MockMXRecord(
                10,
                "mail.example.com.",
            ),
        ]

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    results = get_mx_records("example.com")

    assert results == [
        {
            "priority": 10,
            "server": "mail.example.com",
        }
    ]


def test_get_txt_records(monkeypatch):
    """Test TXT record discovery without real DNS requests."""

    def fake_resolve(domain, record_type):
        assert domain == "example.com"
        assert record_type == "TXT"

        return [
            MockTXTRecord(
                [
                    b"v=spf1 ",
                    b"-all",
                ]
            )
        ]

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    results = get_txt_records("example.com")

    assert results == [
        "v=spf1 -all",
    ]


def test_get_cname_records(monkeypatch):
    """Test CNAME record discovery without real DNS requests."""

    def fake_resolve(domain, record_type):
        assert domain == "www.example.com"
        assert record_type == "CNAME"

        return [
            MockCNAMERecord("example.com."),
        ]

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    results = get_cname_records(
        "www.example.com"
    )

    assert results == [
        "example.com",
    ]