from pyhunter.ingestion.authlog_reader import parse_line, parse_file


def test_parse_failed_password():
    line = "Nov 20 10:02:10 victim sshd[811]: Failed password for root from 192.168.56.10 port 51020 ssh2"
    e = parse_line(line)
    assert e.event_type == "auth_failure"
    assert e.src_ip == "192.168.56.10"
    assert e.user == "root"
    assert e.dst_port == 22
    assert e.timestamp.hour == 10 and e.timestamp.second == 10


def test_parse_invalid_user():
    line = "Nov 20 10:02:12 victim sshd[811]: Failed password for invalid user admin from 192.168.56.10 port 51024 ssh2"
    assert parse_line(line).user == "admin"


def test_parse_accepted_password():
    line = "Nov 20 10:03:06 victim sshd[820]: Accepted password for root from 192.168.56.10 port 51040 ssh2"
    assert parse_line(line).event_type == "auth_success"


def test_irrelevant_line_is_ignored():
    line = "Nov 20 10:03:07 victim sshd[820]: pam_unix(sshd:session): session opened for user root"
    assert parse_line(line) is None


def test_parse_file_counts():
    events = parse_file("samples/auth_sample.log")
    assert len(events) == 5
    assert sum(e.event_type == "auth_failure" for e in events) == 4