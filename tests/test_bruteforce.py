from datetime import datetime, timedelta
from pyhunter.models import Event
from pyhunter.ingestion.authlog_reader import parse_file
from pyhunter.detection.rules import load_rule
from pyhunter.detection.bruteforce import detect_bruteforce

START = datetime(2026, 11, 20, 10, 2, 0)
RULE_PATH = "rules/ssh_bruteforce.yml"


def make_failures(ip, count, step_seconds):
    return [
        Event(START + timedelta(seconds=i * step_seconds), "auth.log",
              "auth_failure", src_ip=ip, dst_port=22, user="root")
        for i in range(count)
    ]


def test_burst_triggers_alert():
    alerts = detect_bruteforce(make_failures("192.168.56.10", 12, 2), load_rule(RULE_PATH))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_name == "ssh_bruteforce"
    assert a.severity == "high"
    assert a.mitre_id == "T1110"
    assert a.src_ip == "192.168.56.10"
    assert a.count == 12
    assert len(a.evidence) == 12


def test_slow_failures_do_not_trigger():
    # one failure every 30 s: the 60 s window never holds more than 3
    alerts = detect_bruteforce(make_failures("10.0.0.5", 12, 30), load_rule(RULE_PATH))
    assert alerts == []


def test_too_few_failures_do_not_trigger():
    alerts = detect_bruteforce(make_failures("10.0.0.5", 5, 1), load_rule(RULE_PATH))
    assert alerts == []


def test_each_ip_is_counted_separately():
    events = make_failures("192.168.56.10", 12, 2) + make_failures("10.0.0.5", 5, 2)
    alerts = detect_bruteforce(events, load_rule(RULE_PATH))
    assert [a.src_ip for a in alerts] == ["192.168.56.10"]


def test_success_events_are_ignored():
    events = [Event(START + timedelta(seconds=i), "auth.log", "auth_success", src_ip="1.1.1.1")
              for i in range(20)]
    assert detect_bruteforce(events, load_rule(RULE_PATH)) == []


def test_end_to_end_from_log_file(tmp_path):
    lines = [
        f"Nov 20 10:02:{i:02d} victim sshd[811]: Failed password for root "
        f"from 192.168.56.10 port {51000 + i} ssh2"
        for i in range(12)
    ]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n")

    alerts = detect_bruteforce(parse_file(str(log)), load_rule(RULE_PATH))
    assert len(alerts) == 1
    assert alerts[0].count == 12