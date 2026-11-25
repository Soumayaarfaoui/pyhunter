import re
from datetime import datetime
from pyhunter.models import Event

LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)


def parse_line(line, year=2026):
    m = LINE.match(line)
    if not m:
        return None
    ts = datetime.strptime(f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    event_type = "auth_failure" if m["result"] == "Failed" else "auth_success"
    return Event(ts, "auth.log", event_type,
                 src_ip=m["ip"], dst_port=22, user=m["user"],
                 extra={"src_port": int(m["port"])})


def parse_file(path, year=2026):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line.rstrip("\n"), year)
            if event:
                events.append(event)
    return events