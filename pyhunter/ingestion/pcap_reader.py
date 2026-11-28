from datetime import datetime, timezone

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader   # reads a PCAP one packet at a time (low memory use)

from pyhunter.models import Event

# TCP flags are stored as bits inside one number. These two are the ones we need.
SYN = 0x02   # "I want to start a connection"
ACK = 0x10   # "I acknowledge your packet"


def _to_datetime(ts):
    """A PCAP stores time as seconds since 1970. Convert it to a normal datetime (UTC)."""
    # replace(tzinfo=None) removes the timezone label so PCAP times look like the auth.log times
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).replace(tzinfo=None)


def parse_packet(pkt):
    """Turn ONE Scapy packet into an Event, or return None if we do not care about it."""
    if not pkt.haslayer(IP):      # we only care about IP traffic
        return None
    ip = pkt[IP]                  # the IP part of the packet (source and destination addresses)
    ts = _to_datetime(pkt.time)

    # Case 1: a TCP packet -> is it a connection attempt (SYN)?
    if pkt.haslayer(TCP):
        flags = int(pkt[TCP].flags)
        # SYN set AND ACK not set = a brand-new connection attempt.
        # (SYN+ACK is the server's reply: ignoring it avoids counting each connection twice.)
        if flags & SYN and not flags & ACK:
            return Event(ts, "pcap", "tcp_syn",
                         src_ip=ip.src, dst_ip=ip.dst, dst_port=pkt[TCP].dport)
        return None

    # Case 2: a DNS packet -> is it a question (a query)?
    if pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        if pkt[DNS].qr == 0:   # qr = 0 means "question", qr = 1 means "answer"
            name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")   # bytes -> text
            return Event(ts, "pcap", "dns_query",
                         src_ip=ip.src, dst_ip=ip.dst, dst_port=53,
                         extra={"query": name})   # keep the domain for the DNS detector later

    return None   # any other packet is not interesting

def read_pcap(path):
    """Read a whole PCAP file and return the list of Events found in it."""
    events = []                        # 'events' (with an s) = the LIST we will return
    with PcapReader(path) as reader:   # the 'with' closes the file automatically
        for pkt in reader:
            event = parse_packet(pkt)  # 'event' (no s) = ONE Event, or None
            if event:                  # keep only the packets that became Events
                events.append(event)   # put that one Event into the list
    return events                      # give back the whole list, after the loop is finished