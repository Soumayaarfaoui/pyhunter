from datetime import datetime
from pyhunter.models import Event, Alert


def test_event_required_and_default_fields():
    e = Event(datetime(2026, 11, 20, 10, 2, 14), "auth.log", "auth_failure",
              src_ip="192.168.56.10", user="root")
    assert e.src_ip == "192.168.56.10"
    assert e.user == "root"
    assert e.dst_port is None       # optional field defaults to None
    assert e.extra == {}


def test_events_do_not_share_extra_dict():
    a = Event(datetime.now(), "pcap", "tcp_syn")
    b = Event(datetime.now(), "pcap", "tcp_syn")
    a.extra["flag"] = "S"
    assert b.extra == {}            # b must stay untouched


def test_alert_holds_evidence():
    t = datetime(2026, 11, 20, 10, 2, 14)
    ev = Event(t, "auth.log", "auth_failure", src_ip="10.0.0.5")
    alert = Alert("ssh_bruteforce", "high", "T1110", "10.0.0.5", t, t, 1, evidence=[ev])
    assert alert.count == 1
    assert alert.evidence[0].src_ip == "10.0.0.5"
    assert alert.reputation == {}