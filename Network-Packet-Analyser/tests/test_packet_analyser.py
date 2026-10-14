import csv
import io
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import packet_analyser as analyzer

from scapy.all import IP, TCP, UDP, ICMP, ARP

@pytest.fixture(autouse=True)
def reset_statistics():
    """Reset statistics before each test."""

    analyzer.packet_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Other": 0,
    }

    analyzer.total_packets = 0
    analyzer.total_bytes = 0


def test_identify_tcp():
    """Check that TCP packets are identified correctly."""

    packet = IP() / TCP()

    assert analyzer.identify_protocol(packet) == "TCP"


def test_identify_udp():
    """Check that UDP packets are identified correctly."""

    packet = IP() / UDP()

    assert analyzer.identify_protocol(packet) == "UDP"


def test_identify_icmp():
    """Check that ICMP packets are identified correctly."""

    packet = IP() / ICMP()

    assert analyzer.identify_protocol(packet) == "ICMP"


def test_identify_other():
    """Check that other IPv4 packets are classified correctly."""

    packet = IP() / "test data"

    assert analyzer.identify_protocol(packet) == "Other"


def test_analyze_tcp_packet():
    """Check packet analysis, CSV export, and statistics."""

    packet = (
        IP(src="192.0.2.1", dst="198.51.100.1")
        / TCP(sport=12345, dport=443)
    )

    output = io.StringIO()

    writer = csv.DictWriter(
        output,
        fieldnames=analyzer.CSV_FIELDS,
    )

    writer.writeheader()

    analyzer.analyze_packet(
        packet,
        writer,
        output,
    )

    output.seek(0)

    rows = list(csv.DictReader(output))

    assert len(rows) == 1

    assert rows[0]["Source IP"] == "192.0.2.1"
    assert rows[0]["Destination IP"] == "198.51.100.1"
    assert rows[0]["Source Port"] == "12345"
    assert rows[0]["Destination Port"] == "443"
    assert rows[0]["Protocol"] == "TCP"

    assert analyzer.total_packets == 1
    assert analyzer.packet_counts["TCP"] == 1
    assert analyzer.total_bytes == len(packet)


def test_non_ipv4_packet_is_ignored():
    """Check that non-IPv4 packets don't affect statistics."""

    packet = ARP()

    output = io.StringIO()

    writer = csv.DictWriter(
        output,
        fieldnames=analyzer.CSV_FIELDS,
    )

    writer.writeheader()

    analyzer.analyze_packet(
        packet,
        writer,
        output,
    )

    assert analyzer.total_packets == 0
    assert analyzer.total_bytes == 0

    assert sum(analyzer.packet_counts.values()) == 0

    output.seek(0)

    rows = list(csv.DictReader(output))

    assert len(rows) == 0
