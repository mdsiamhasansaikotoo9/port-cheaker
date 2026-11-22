#!/usr/bin/env python3
"""
Port Checker - shows which network ports are open on a device.

A "port" is a numbered door a program listens on.
Example: a web server usually listens on port 80 (http) or 443 (https).

Uses only Python's standard library. Nothing to install.

How to run:
    python port_checker.py                       (your own computer, common ports)
    python port_checker.py 192.168.1.1           (your router, common ports)
    python port_checker.py 192.168.1.1 -p 80,443,8080
    python port_checker.py localhost -p 1-1024   (a range of ports)
    python port_checker.py localhost --all       (show closed ports too)

Results:
    OPEN      a program is listening and accepted the connection
    CLOSED    the device answered "nothing here"
    FILTERED  no answer at all (often a firewall is blocking it)

IMPORTANT: Only check devices you own or have permission to check.
"""

import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

MAX_PORTS = 5000

COMMON_PORTS = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP (email)",
    53: "DNS", 67: "DHCP", 80: "HTTP (web)", 110: "POP3 (email)",
    123: "NTP (time)", 135: "Windows RPC", 139: "NetBIOS", 143: "IMAP (email)",
    161: "SNMP", 443: "HTTPS (secure web)", 445: "SMB (file sharing)",
    587: "SMTP submission", 993: "IMAPS", 995: "POP3S", 1433: "MS SQL Server",
    1883: "MQTT", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP (alt)", 8080: "HTTP (alt)",
    8443: "HTTPS (alt)", 27017: "MongoDB",
}


def parse_ports(text):
    """Turn '22,80,8000-8010' into a sorted list of port numbers."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if not (a.strip().isdigit() and b.strip().isdigit()):
                raise ValueError(f"'{part}' is not a valid range. Example: 20-25")
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        elif part.isdigit():
            ports.add(int(part))
        else:
            raise ValueError(f"'{part}' is not a port number.")
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Ports must be between 1 and 65535 (got {bad[0]}).")
    return sorted(ports)


def check_port(ip, port, timeout):
    """Try to connect. Returns 'OPEN', 'CLOSED' or 'FILTERED'."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return "OPEN"
        except ConnectionRefusedError:
            return "CLOSED"
        except socket.timeout:
            return "FILTERED"
        except OSError:
            return "FILTERED"


def is_own_network(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local


def main():
    parser = argparse.ArgumentParser(description="Check which ports are open on a device.")
    parser.add_argument("host", nargs="?", default="localhost",
                        help="device name or IP (default: localhost = this computer)")
    parser.add_argument("-p", "--ports", help="ports, e.g. 22,80,443 or 1-1024 (default: common ports)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="seconds to wait per port (default: 1)")
    parser.add_argument("--all", action="store_true", help="also list closed and filtered ports")
    args = parser.parse_args()

    # Which ports?
    try:
        ports = parse_ports(args.ports) if args.ports else sorted(COMMON_PORTS)
    except ValueError as e:
        sys.exit(f"Error: {e}")
    if len(ports) > MAX_PORTS:
        sys.exit(f"Error: {len(ports)} ports is too many. The limit is {MAX_PORTS}.")

    # Find the IP address
    try:  # prefer IPv4 (on Windows, "localhost" may resolve to IPv6 first)
        ip = socket.getaddrinfo(args.host, None, socket.AF_INET)[0][4][0]
    except socket.gaierror:
        try:
            ip = socket.getaddrinfo(args.host, None)[0][4][0]
        except socket.gaierror:
            sys.exit(f"Error: could not find the device '{args.host}'. Check the name or IP.")

    # Safety check for devices outside your own network
    if not is_own_network(ip):
        print(f"WARNING: {args.host} ({ip}) is outside your local network.")
        print("Checking ports on devices you don't own can break rules or laws.")
        answer = input("Do you own this device or have permission to check it? (yes/no): ")
        if answer.strip().lower() not in ("yes", "y"):
            sys.exit("Stopped. Nothing was checked.")

    try:  # make sure this computer can use this kind of address (IPv4 or IPv6)
        socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET).close()
    except OSError:
        sys.exit(f"Error: this computer cannot connect to IPv6 addresses like {ip}.")

    print(f"Checking {len(ports)} port(s) on {args.host} ({ip})...\n")
    start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(lambda p: (p, check_port(ip, p, args.timeout)), ports))

    counts = {"OPEN": 0, "CLOSED": 0, "FILTERED": 0}
    for port, status in results:
        counts[status] += 1
        if status == "OPEN" or args.all:
            name = COMMON_PORTS.get(port, "")
            print(f"  {port:>5}  {status:8}  {name}")

    if counts["OPEN"] == 0 and not args.all:
        print("  No open ports found.")

    elapsed = time.perf_counter() - start
    print(f"\nDone in {elapsed:.1f}s. Open: {counts['OPEN']}, "
          f"Closed: {counts['CLOSED']}, Filtered: {counts['FILTERED']}")


if __name__ == "__main__":
    main()
