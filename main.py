#!/usr/bin/env python3
"""
Fast Full Port Scanner (Threaded)

Scans all TCP ports (1–65535) on a target IP or hostname.
Uses multithreading to dramatically improve speed.
For learning and basic security testing only.
"""

import socket
import sys
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common services and descriptions
SERVICE_DESCRIPTIONS = {
    "ssh": "Secure remote access",
    "http": "Web traffic (not encrypted)",
    "https": "Secure web traffic",
    "ftp": "File transfers",
    "smtp": "Sending email",
    "dns": "Domain name lookups",
    "telnet": "Remote access (unsafe)",
    "pop3": "Downloading email",
    "imap": "Email access",
}


def is_valid_target(target):
    """Check if input looks like an IP or hostname"""
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    hostname_pattern = r"^[a-zA-Z0-9.-]+$"
    return re.match(ip_pattern, target) or re.match(hostname_pattern, target)


def scan_port(target_ip, port):
    """Attempt to connect to a TCP port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.15)
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"

            description = SERVICE_DESCRIPTIONS.get(
                service.lower(), "No description available"
            )

            return port, service.upper(), description
    except:
        pass

    return None


def main():
    print("=" * 60)
    print(" Fast Python Port Scanner")
    print(" Multithreaded • Learning Use")
    print("=" * 60)

    target = input("Enter IP address or website: ").strip()

    if not is_valid_target(target):
        print("[!] Invalid target format.")
        sys.exit(1)

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Could not resolve target.")
        sys.exit(1)

    print("\n[+] Target:", target)
    print("[+] IP Address:", target_ip)
    print("[+] Scanning ports 1–65535")
    print("[+] Started at:", datetime.now().strftime("%H:%M:%S"))
    print("\nScanning...\n")

    open_ports = []
    MAX_THREADS = 500  # adjust if needed

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port)
            for port in range(1, 65536)
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    if open_ports:
        print("Open ports found:\n")
        for port, service, description in sorted(open_ports):
            print(f"- {port:<6} {service:<8} | {description}")
    else:
        print("No open ports found.")

    print("\n[+] Scan finished at:", datetime.now().strftime("%H:%M:%S"))


if __name__ == "__main__":
    main()
