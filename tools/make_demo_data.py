"""Generate SYNTHETIC lab evidence for PyHunter (no real traffic is used or captured)."""
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR     # DNS layers: DNS = the message, DNSQR = the question
from scapy.layers.inet import IP, TCP, UDP  # network layers: IP address, TCP and UDP
from scapy.layers.l2 import Ether           # the Ethernet layer (the outer "envelope" of a packet)
from scapy.utils import wrpcap              # writes a list of packets into a .pcap file

# The "actors" of our story. All addresses are private lab addresses.
ATTACKER = "192.168.56.10"    # the bad machine (like your Kali VM)
VICTIM = "192.168.56.20"      # the machine being attacked (like your Ubuntu VM)
USER_PC = "192.168.56.30"     # a normal user: used to prove we do NOT alert on normal behavior
DNS_SERVER = "192.168.56.1"   # the DNS server the victim asks for domain names

OUT = Path("samples/demo")    # where the generated files will be saved

# Time zero of the story: 20 Nov 2026, 10:00:00 UTC, converted to a Unix timestamp (a plain number)
BASE = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc).timestamp()

# A random generator with a FIXED seed: it gives the same "random" values on every run,
# so the files are identical each time (good for tests and for screenshots).
rng = random.Random(42)


def syn(t, src, dst, port):
    """Build one TCP SYN packet (the first packet of a connection attempt) at time t."""
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=rng.randint(40000, 60000), dport=port, flags="S")
    pkt.time = t   # set the capture time, otherwise every packet would get "now"
    return pkt


def dns_query(t, src, name):
    """Build one DNS question ("what is the IP of <name>?") at time t."""
    pkt = (Ether() / IP(src=src, dst=DNS_SERVER) / UDP(sport=rng.randint(40000, 60000), dport=53)
           / DNS(rd=1, qd=DNSQR(qname=name)))
    pkt.time = t
    return pkt


def random_domain():
    """Make a random-looking domain such as 'x8f2kq9zpl3m1a0b.xyz' (what malware often does)."""
    chars = string.ascii_lowercase + string.digits
    return "".join(rng.choice(chars) for _ in range(16)) + rng.choice([".com", ".net", ".xyz"])


def build_pcap():
    """Build the list of packets that tell the attack story."""
    packets = []

    # 1. The attacker port-scans 100 different ports in about 5 seconds (like nmap)
    for i, port in enumerate(rng.sample(range(1, 1025), 100)):
        packets.append(syn(BASE + 5 + i * 0.05, ATTACKER, VICTIM, port))

    # 2. A normal user makes a few ordinary connections (SSH = 22, web = 80)
    for t, port in [(2, 22), (10, 80), (40, 22), (60, 80)]:
        packets.append(syn(BASE + t, USER_PC, VICTIM, port))

    # 3. The victim does normal DNS lookups, far apart in time
    for i, name in enumerate(["google.com", "ubuntu.com", "github.com", "archive.ubuntu.com"]):
        packets.append(dns_query(BASE + 1 + i * 100, VICTIM, name))

    # 4. C2 simulation: the victim suddenly asks for 12 random-looking domains
    for i in range(12):
        packets.append(dns_query(BASE + 400 + i * 5, VICTIM, random_domain()))

    packets.sort(key=lambda p: p.time)   # a real capture is in time order
    return packets


def auth_line(dt, pid, text):
    """Format one line exactly like a real Linux auth.log line."""
    return f"{dt.strftime('%b %d %H:%M:%S')} victim sshd[{pid}]: {text}"


def build_auth_log():
    """Build the SSH login history of the victim."""
    lines = []

    # A normal user mistypes the password once, then logs in correctly
    t = datetime(2026, 11, 20, 9, 58, 0)
    lines.append(auth_line(t, 700, f"Failed password for alice from {USER_PC} port 50100 ssh2"))
    lines.append(auth_line(t + timedelta(seconds=10), 701,
                           f"Accepted password for alice from {USER_PC} port 50102 ssh2"))

    # The attacker's brute force: 50 failed logins, one per second
    t = datetime(2026, 11, 20, 10, 2, 0)
    users = ["root", "admin", "ubuntu", "test"]   # usernames the attacker guesses
    for i in range(50):
        user = users[i % 4]
        prefix = "" if user == "root" else "invalid user "   # real logs say this for unknown users
        lines.append(auth_line(t + timedelta(seconds=i), 811,
                               f"Failed password for {prefix}{user} from {ATTACKER} port {51000 + i} ssh2"))

    # Finally the attacker guesses right and gets in
    lines.append(auth_line(t + timedelta(seconds=52), 820,
                           f"Accepted password for root from {ATTACKER} port 51100 ssh2"))
    return lines


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)   # create samples/demo if it does not exist

    packets = build_pcap()
    wrpcap(str(OUT / "attack.pcap"), packets)
    print(f"Wrote {OUT / 'attack.pcap'} ({len(packets)} packets)")

    lines = build_auth_log()
    (OUT / "auth_attack.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT / 'auth_attack.log'} ({len(lines)} lines)")