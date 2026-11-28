from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from pyhunter.ingestion.pcap_reader import read_pcap


def make_packet(layers, t):
    """Build a small test packet with a chosen capture time."""
    pkt = Ether() / layers
    pkt.time = t
    return pkt


def test_syn_and_dns_are_extracted(tmp_path):
    # ARRANGE: one SYN packet and one DNS question, saved into a temporary PCAP
    packets = [
        make_packet(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80, flags="S"), 1000.0),
        make_packet(IP(src="1.1.1.1", dst="9.9.9.9") / UDP(dport=53)
                    / DNS(rd=1, qd=DNSQR(qname="evil.example.com")), 1001.0),
    ]
    path = tmp_path / "t.pcap"
    wrpcap(str(path), packets)

    # ACT: read it back
    events = read_pcap(str(path))

    # ASSERT: both packets became the right kind of Event
    assert [e.event_type for e in events] == ["tcp_syn", "dns_query"]
    assert events[0].src_ip == "1.1.1.1"
    assert events[0].dst_port == 80
    assert events[1].extra["query"] == "evil.example.com"


def test_syn_ack_and_plain_ack_are_ignored(tmp_path):
    # Replies (SYN+ACK) and acknowledgements (ACK) must NOT become Events
    packets = [
        make_packet(IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=80, flags="SA"), 1000.0),
        make_packet(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80, flags="A"), 1001.0),
    ]
    path = tmp_path / "t.pcap"
    wrpcap(str(path), packets)
    assert read_pcap(str(path)) == []