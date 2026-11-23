#!/usr/bin/env python3
"""Long-run (soak) test for the trapsnmp gateway.

Run it next to a running gateway for 24-48 hours. It:
  * sends steady SNMPv2c traps to the gateway (like real devices would),
  * records the gateway's memory, open files, and threads every few minutes,
  * optionally reads the console for traps received, dropped, and rejected,
  * prints a verdict: memory flat or growing.

Only the Python standard library is needed. Memory is read from /proc on
Linux; on other systems install psutil.

Examples
  # 24 hours, 5 traps/s to UDP 162, sample every 5 minutes
  python3 soak_test.py --pid $(pgrep -f "python.* -m trapsnmp") --hours 24

  # Also read the console (counts traps the gateway processed)
  python3 soak_test.py --pid 1234 --hours 48 --console http://127.0.0.1:8080 --password 'P@ssw0rd'

  # Receiver on 1162 (gateway not running as root)
  python3 soak_test.py --pid 1234 --target 127.0.0.1:1162

Stop early with Ctrl+C; the verdict is printed for what was recorded.
"""

from __future__ import annotations

import argparse
import csv
import http.cookiejar
import json
import os
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

# --------------------------------------------------------------------------
# Minimal BER encoding for an SNMPv2c trap (RFC 3416), no extra packages.
# --------------------------------------------------------------------------


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _int_body(n: int) -> bytes:
    size = max(1, (n.bit_length() + 8) // 8)
    return n.to_bytes(size, "big", signed=True)


def ber_integer(n: int, tag: int = 0x02) -> bytes:
    return _tlv(tag, _int_body(n))


def ber_unsigned(n: int, tag: int) -> bytes:
    # Counter32 / Gauge32 / TimeTicks: unsigned, but a leading 0 keeps it positive.
    body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _tlv(tag, body)


def ber_octets(data: bytes) -> bytes:
    return _tlv(0x04, data)


def ber_oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.strip(".").split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return _tlv(0x06, bytes(body))


def ber_sequence(*items: bytes, tag: int = 0x30) -> bytes:
    return _tlv(tag, b"".join(items))


TIMETICKS = 0x43
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"

# A fixed set of trap types, like a real plant: memory must stay flat for these.
TRAP_MIX = [
    ("1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.4", "int", 4), ("1.3.6.1.2.1.2.2.1.8.4", "int", 2)]),  # linkDown
    ("1.3.6.1.6.3.1.1.5.4", [("1.3.6.1.2.1.2.2.1.1.4", "int", 4), ("1.3.6.1.2.1.2.2.1.8.4", "int", 1)]),  # linkUp
    ("1.3.6.1.6.3.1.1.5.1", [("1.3.6.1.2.1.1.5.0", "str", "soak-test")]),  # coldStart
    ("1.3.6.1.4.1.99999.1.1", [("1.3.6.1.4.1.99999.1.1.2.0", "str", "Rack A"), ("1.3.6.1.4.1.99999.1.1.1.0", "int", 82)]),
    ("1.3.6.1.4.1.4130.10.2.5.1.2.2.1.6",
     [("1.3.6.1.4.1.4130.10.2.5.1.2.2.1.6.1.0.26.139.1.2.3", "int", -72)]),  # GE remote RSSI
]


def build_trap(community: str, request_id: int, uptime: int, trap_oid: str, binds) -> bytes:
    varbinds = [
        ber_sequence(ber_oid(SYS_UPTIME), ber_unsigned(uptime % 2**32, TIMETICKS)),
        ber_sequence(ber_oid(SNMP_TRAP_OID), ber_oid(trap_oid)),
    ]
    for oid, kind, value in binds:
        encoded = ber_integer(value) if kind == "int" else ber_octets(str(value).encode())
        varbinds.append(ber_sequence(ber_oid(oid), encoded))
    pdu = ber_sequence(
        ber_integer(request_id),
        ber_integer(0),
        ber_integer(0),
        ber_sequence(*varbinds),
        tag=0xA7,  # SNMPv2-Trap-PDU
    )
    return ber_sequence(ber_integer(1), ber_octets(community.encode()), pdu)  # version 1 = v2c


class TrapSender(threading.Thread):
    def __init__(self, host: str, port: int, community: str, rate: float) -> None:
        super().__init__(daemon=True)
        self.address = (host, port)
        self.community = community
        self.rate = rate
        self.sent = 0
        self.errors = 0
        self.stop = threading.Event()

    def run(self) -> None:
        if self.rate <= 0:
            return
        family = socket.AF_INET6 if ":" in self.address[0] else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        started = time.monotonic()
        interval = 1.0 / self.rate
        next_at = started
        while not self.stop.is_set():
            trap_oid, binds = TRAP_MIX[self.sent % len(TRAP_MIX)]
            uptime = int((time.monotonic() - started) * 100)
            packet = build_trap(self.community, random.randint(1, 2**31 - 1), uptime, trap_oid, binds)
            try:
                sock.sendto(packet, self.address)
                self.sent += 1
            except OSError:
                self.errors += 1
            next_at += interval
            delay = next_at - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            else:
                next_at = time.monotonic()
        sock.close()


# --------------------------------------------------------------------------
# Process statistics
# --------------------------------------------------------------------------


def process_stats(pid: int) -> dict:
    status = f"/proc/{pid}/status"
    if os.path.isdir("/proc/self"):
        if not os.path.exists(status):
            raise ProcessLookupError(pid)
        values = {}
        with open(status, encoding="ascii", errors="replace") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                values[key] = rest.strip()
        rss_kb = int(values.get("VmRSS", "0 kB").split()[0])
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        return {"rss_mb": rss_kb / 1024, "fds": fds, "threads": int(values.get("Threads", "0"))}
    try:
        import psutil  # type: ignore
    except ImportError:
        sys.exit("Cannot read process memory here: no /proc. Install psutil (pip install psutil).")
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess as exc:
        raise ProcessLookupError(pid) from exc
    fds = proc.num_fds() if hasattr(proc, "num_fds") else proc.num_handles()
    return {"rss_mb": proc.memory_info().rss / 2**20, "fds": fds, "threads": proc.num_threads()}


# --------------------------------------------------------------------------
# Optional console reader
# --------------------------------------------------------------------------


class Console:
    def __init__(self, base: str, password: str) -> None:
        self.base = base.rstrip("/")
        self.password = password
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self.signed_in = False
        self.disabled = ""

    def _login(self) -> None:
        request = urllib.request.Request(
            self.base + "/api/login",
            data=json.dumps({"password": self.password}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            self.opener.open(request, timeout=10).read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 429):
                # Stop here: retrying a wrong password would trip the console lockout.
                self.disabled = f"sign-in refused (HTTP {exc.code}); console counts are skipped from now on"
            raise
        self.signed_in = True

    def state(self) -> dict:
        for attempt in (1, 2):
            if not self.signed_in:
                self._login()
            try:
                with self.opener.open(self.base + "/api/state", timeout=15) as response:
                    return json.loads(response.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 1:
                    self.signed_in = False  # session ended; sign in again once
                    continue
                raise
        return {}


def console_numbers(state: dict) -> dict:
    snmp = state.get("snmp") or {}
    counts = state.get("counts") or {}
    tags = state.get("tags") or {}
    rejected = snmp.get("rejected") or {}
    return {
        "traps": counts.get("traps", ""),
        "dropped": snmp.get("dropped", ""),
        "rejected": sum(int(v or 0) for v in rejected.values()) if rejected else 0,
        "tags_used": tags.get("tagsUsed", ""),
    }


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------


def slope_per_hour(rows: list[dict], key: str) -> float:
    """Least-squares slope of key over time, in units per hour."""
    points = [(r["elapsed_h"], float(r[key])) for r in rows]
    if len(points) < 3:
        return 0.0
    n = len(points)
    mean_x = sum(x for x, _ in points) / n
    mean_y = sum(y for _, y in points) / n
    var_x = sum((x - mean_x) ** 2 for x, _ in points)
    if var_x == 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / var_x


def verdict(rows: list[dict], rss_limit: float) -> str:
    if len(rows) < 4:
        return "Not enough samples for a verdict yet."
    total_h = rows[-1]["elapsed_h"]
    # Ignore warm-up: the first 20% of the run (at least one sample).
    start = max(1, len(rows) // 5)
    steady = rows[start:]
    rss_slope = slope_per_hour(steady, "rss_mb")
    fd_slope = slope_per_hour(steady, "fds")
    first, last = steady[0], steady[-1]
    lines = [
        f"Recorded {total_h:.1f} h, {len(rows)} samples. After warm-up:",
        f"  memory {first['rss_mb']:.1f} -> {last['rss_mb']:.1f} MB, trend {rss_slope:+.2f} MB/hour "
        f"({rss_slope * 24 * 30:+.0f} MB a month if it continued)",
        f"  open files {first['fds']} -> {last['fds']}, trend {fd_slope:+.2f}/hour",
        f"  threads {first['threads']} -> {last['threads']}",
    ]
    if "dropped" in last and last.get("dropped") not in ("", None):
        lines.append(
            f"  console: traps {last['traps']}, dropped {last['dropped']}, rejected {last['rejected']}, "
            f"trap tags used {last['tags_used']}"
        )
    # A trend alone over-reacts to small wobbles in short runs, so also require
    # real growth: at least 3 MB and 3% between the start and end of the steady part.
    rise = last["rss_mb"] - first["rss_mb"]
    growing = rss_slope > rss_limit and rise > max(3.0, 0.03 * first["rss_mb"])
    fd_growing = fd_slope > 0.5 and last["fds"] > first["fds"] + 5
    if growing or fd_growing:
        what = []
        if growing:
            what.append(f"memory keeps rising ({rss_slope:+.2f} MB/hour, about {rss_slope * 24:+.0f} MB/day)")
        if fd_growing:
            what.append(f"open files keep rising ({first['fds']} -> {last['fds']})")
        lines.append("VERDICT: POSSIBLE LEAK - " + "; ".join(what) + ". Keep the CSV and the gateway log.")
    elif total_h < 12:
        lines.append(f"VERDICT: flat so far ({total_h:.1f} h). Run at least 24 h for a firm answer.")
    else:
        lines.append("VERDICT: FLAT - no sign of a memory or file-handle leak.")
    return "\n".join(lines)


# --------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pid", type=int, required=True, help="process id of the running gateway")
    parser.add_argument("--hours", type=float, default=24.0, help="how long to run (default 24)")
    parser.add_argument("--every", type=float, default=300.0, help="seconds between samples (default 300)")
    parser.add_argument("--target", default="127.0.0.1:162", help="trap receiver host:port (default 127.0.0.1:162)")
    parser.add_argument("--community", default="public", help="SNMPv2c community (default public)")
    parser.add_argument("--rate", type=float, default=5.0, help="traps per second to send; 0 = none (default 5)")
    parser.add_argument("--console", help="console URL to read counts, e.g. http://127.0.0.1:8080")
    parser.add_argument("--password", help="console password (needed with --console)")
    parser.add_argument("--csv", default="soak.csv", help="where to write samples (default soak.csv)")
    parser.add_argument("--rss-limit", type=float, default=0.2,
                        help="memory trend in MB/hour above which a leak is reported (default 0.2, about 150 MB a month)")
    args = parser.parse_args()

    if args.console and not args.password:
        parser.error("--console needs --password")
    host, _, port = args.target.rpartition(":")
    try:
        process_stats(args.pid)  # fail early if the pid is wrong
    except ProcessLookupError:
        sys.exit(f"No running process with pid {args.pid}. Find the gateway with: pgrep -af trapsnmp")

    sender = TrapSender(host or "127.0.0.1", int(port), args.community, args.rate)
    sender.start()
    console = Console(args.console, args.password) if args.console else None

    fields = ["time", "elapsed_h", "rss_mb", "fds", "threads", "sent", "traps", "dropped", "rejected", "tags_used"]
    rows: list[dict] = []
    started = time.monotonic()
    deadline = started + args.hours * 3600
    print(f"Soak test on pid {args.pid} for {args.hours:g} h, {args.rate:g} traps/s to {args.target}, "
          f"sample every {args.every:g} s -> {args.csv}")
    try:
        with open(args.csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            while True:
                try:
                    stats = process_stats(args.pid)
                except (FileNotFoundError, ProcessLookupError):
                    print("The gateway process has stopped.")
                    break
                except Exception as exc:  # psutil.NoSuchProcess and friends
                    print(f"Cannot read the gateway process: {exc}")
                    break
                row = {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "elapsed_h": round((time.monotonic() - started) / 3600, 4),
                    "rss_mb": round(stats["rss_mb"], 2),
                    "fds": stats["fds"],
                    "threads": stats["threads"],
                    "sent": sender.sent,
                    "traps": "", "dropped": "", "rejected": "", "tags_used": "",
                }
                if console and not console.disabled:
                    try:
                        row.update(console_numbers(console.state()))
                    except Exception as exc:
                        print(f"  (console not read: {console.disabled or exc})")
                rows.append(row)
                writer.writerow(row)
                handle.flush()
                print(f"{row['time']}  {row['elapsed_h']:6.2f} h  memory {row['rss_mb']:8.1f} MB  "
                      f"files {row['fds']:4}  threads {row['threads']:3}  sent {row['sent']}"
                      + (f"  received {row['traps']}  dropped {row['dropped']}  rejected {row['rejected']}"
                         if console else ""))
                if time.monotonic() >= deadline:
                    break
                time.sleep(max(0.0, min(args.every, deadline - time.monotonic())))
    except KeyboardInterrupt:
        print("\nStopped early.")
    finally:
        sender.stop.set()
        sender.join(timeout=5)
    if sender.errors:
        print(f"Send errors: {sender.errors} (is the target address right?)")
    print()
    print(verdict(rows, args.rss_limit))


if __name__ == "__main__":
    main()
