#!/usr/bin/env python3
"""
SSH Intrusion Detection and Prevention System (IDPS)
Monitors SSH authentication logs and automatically bans IPs after failed attempts
Enhanced with complete connection lifecycle logging
"""

import re
import subprocess
import time
from datetime import datetime
from collections import defaultdict
import os

from ssh_idps.config import (
    MAX_ATTEMPTS,
    TIME_WINDOW,
    LIVE_LOG,
    BANNED_LOG
)


class SSHIDPSEngine:
    def __init__(self):
        self.failed_attempts = defaultdict(list)
        self.banned_ips = set()

    # Logging
    def log_event(self, message, log_type="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{log_type}] {message}\n"

        print(log_entry.strip())
        with open(LIVE_LOG, "a") as f:
            f.write(log_entry)

    # Persistence 
    def load_banned_ips(self):
        if not os.path.exists(BANNED_LOG):
            return

        with open(BANNED_LOG, "r") as f:
            for line in f:
                match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if match:
                    self.banned_ips.add(match.group())

        self.log_event(
            f"Loaded {len(self.banned_ips)} previously banned IPs",
            "INIT"
        )

    # Enforcement
    def ban_ip(self, ip, username, attempts):
        if ip in self.banned_ips:
            return

        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )

            self.banned_ips.add(ip)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(BANNED_LOG, "a") as f:
                f.write(f"[{username}, {ip}, {timestamp}, {attempts}, BANNED]\n")

            self.log_event(
                f"IP BANNED | IP: {ip} | User: {username} | "
                f"Attempts: {attempts} | Reason: Brute force detected",
                "SECURITY"
            )

        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to ban IP {ip}: {e}", "ERROR")

    # Detection 
    def check_and_ban(self):
        current_time = time.time()

        for ip, attempts in list(self.failed_attempts.items()):
            self.failed_attempts[ip] = [
                (ts, user) for ts, user in attempts
                if current_time - ts < TIME_WINDOW
            ]

            if (
                len(self.failed_attempts[ip]) >= MAX_ATTEMPTS
                and ip not in self.banned_ips
            ):
                username = self.failed_attempts[ip][0][1]
                self.ban_ip(ip, username, len(self.failed_attempts[ip]))

    # Parsing 
    @staticmethod
    def parse_ssh_log_line(line):
        patterns = {
            "CONNECTION": r'Connection from (\d+\.\d+\.\d+\.\d+) port (\d+)',
            "INVALID_USER": r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)',
            "AUTH_FAIL": r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)',
            "AUTH_SUCCESS": r'Accepted (password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)',
            "DISCONNECT": r'Disconnected from (?:user \S+ )?(\d+\.\d+\.\d+\.\d+) port (\d+)'
        }

        if m := re.search(patterns["CONNECTION"], line):
            return {"type": "CONNECTION", "ip": m.group(1), "port": m.group(2)}

        if m := re.search(patterns["INVALID_USER"], line):
            return {"type": "INVALID_USER", "username": m.group(1), "ip": m.group(2)}

        if m := re.search(patterns["AUTH_FAIL"], line):
            return {
                "type": "AUTH_FAIL",
                "username": m.group(1),
                "ip": m.group(2),
                "port": m.group(3),
                "method": "password"
            }

        if m := re.search(patterns["AUTH_SUCCESS"], line):
            return {
                "type": "AUTH_SUCCESS",
                "method": m.group(1),
                "username": m.group(2),
                "ip": m.group(3),
                "port": m.group(4)
            }

        if m := re.search(patterns["DISCONNECT"], line):
            return {"type": "DISCONNECT", "ip": m.group(1), "port": m.group(2)}

        return None

    # Monitor
    def monitor(self):
        self.log_event("SSH IDPS Started - Monitoring for intrusions...", "INIT")
        self.load_banned_ips()

        process = subprocess.Popen(
            ["sudo", "journalctl", "-u", "sshd", "-f", "-n", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        self.log_event("Monitoring journalctl for SSH events...", "INIT")

        for line in process.stdout:
            event = self.parse_ssh_log_line(line)
            if not event:
                continue

            etype = event["type"]
            ip = event.get("ip")

            if etype == "CONNECTION":
                self.log_event(
                    f"Connection request | IP: {ip} | Port: {event['port']}",
                    "CONNECTION"
                )

            elif etype == "INVALID_USER":
                self.log_event(
                    f"Invalid user | User: {event['username']} | IP: {ip}",
                    "WARNING"
                )

            elif etype == "AUTH_FAIL":
                ts = time.time()
                self.failed_attempts[ip].append((ts, event["username"]))

                self.log_event(
                    f"Auth failed | User: {event['username']} | IP: {ip} | "
                    f"Attempt: {len(self.failed_attempts[ip])}/{MAX_ATTEMPTS}",
                    "AUTH_FAIL"
                )

                self.check_and_ban()

            elif etype == "AUTH_SUCCESS":
                self.log_event(
                    f"Auth success | User: {event['username']} | IP: {ip}",
                    "AUTH_SUCCESS"
                )
                self.failed_attempts.pop(ip, None)

            elif etype == "DISCONNECT":
                self.log_event(
                    f"Session ended | IP: {ip} | Port: {event['port']}",
                    "DISCONNECT"
                )


def main():
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        exit(1)

    for file in (LIVE_LOG, BANNED_LOG):
        if not os.path.exists(file):
            open(file, "a").close()

    engine = SSHIDPSEngine()
    engine.monitor()


if __name__ == "__main__":
    main()

