from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    """One normalized thing that happened (a login failure, a packet, a DNS query)."""
    timestamp: datetime
    source: str                 # where it came from: "auth.log", "pcap"
    event_type: str             # "auth_failure", "auth_success", "tcp_syn", "dns_query"
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    user: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class Alert:
    """One detection result produced by a detector."""
    rule_name: str
    severity: str               # "low", "medium", "high", "critical"
    mitre_id: str               # for example "T1110"
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    evidence: list = field(default_factory=list)    # the Events that triggered it
    reputation: dict = field(default_factory=dict)  # filled later by VirusTotal