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

# Configuration
MAX_ATTEMPTS = 5  # Number of failed attempts before banning
TIME_WINDOW = 300  # Time window in seconds (5 minutes)
LOG_FILE = "/var/log/auth.log"  # SSH auth log location (use journalctl for systemd)
LIVE_LOG = "idps_live_log.txt"
BANNED_LOG = "banned_ips.txt"
CHECK_INTERVAL = 2  # Seconds between log checks

# Track failed attempts: {IP: [(timestamp, username), ...]}
failed_attempts = defaultdict(list)
banned_ips = set()

def log_event(message, log_type="INFO"):
    """Log events to live log file with timestamps"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{log_type}] {message}\n"
    
    print(log_entry.strip())  # Console output
    
    with open(LIVE_LOG, "a") as f:
        f.write(log_entry)

def load_banned_ips():
    """Load previously banned IPs from file"""
    if os.path.exists(BANNED_LOG):
        with open(BANNED_LOG, "r") as f:
            for line in f:
                # Extract IP from banned log format
                match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if match:
                    banned_ips.add(match.group())
        log_event(f"Loaded {len(banned_ips)} previously banned IPs", "INIT")

def ban_ip(ip, username, attempts):
    """Ban an IP address using iptables"""
    if ip in banned_ips:
        return
    
    try:
        # Add iptables rule to DROP packets from this IP
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True
        )
        
        banned_ips.add(ip)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log to banned IPs file
        ban_entry = f"[{username}, {ip}, {timestamp}, {attempts}, BANNED]\n"
        with open(BANNED_LOG, "a") as f:
            f.write(ban_entry)
        
        log_event(f"IP BANNED | IP: {ip} | User: {username} | Total attempts: {attempts} | Reason: Brute force detected", "SECURITY")
        
    except subprocess.CalledProcessError as e:
        log_event(f"Failed to ban IP {ip}: {e}", "ERROR")

def parse_ssh_log_line(line):
    """Parse SSH authentication log line for connection, failed and successful attempts"""
    
    # Pattern for connection request
    # Example: "Nov  9 10:30:45 hostname sshd[12345]: Connection from 192.168.1.100 port 54321"
    connection_pattern = r'Connection from (\d+\.\d+\.\d+\.\d+) port (\d+)'
    
    # Pattern for failed password attempts
    # Example: "Nov  9 10:30:45 hostname sshd[12345]: Failed password for testuser from 192.168.1.100 port 12345 ssh2"
    failed_pattern = r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
    
    # Pattern for successful login
    # Example: "Nov  9 10:30:45 hostname sshd[12345]: Accepted password for testuser from 192.168.1.100 port 12345 ssh2"
    success_pattern = r'Accepted (password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
    
    # Pattern for invalid user
    # Example: "Invalid user admin from 192.168.1.100 port 54321"
    invalid_user_pattern = r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
    
    # Pattern for disconnection
    # Example: "Disconnected from 192.168.1.100 port 54321"
    disconnect_pattern = r'Disconnected from (?:user \S+ )?(\d+\.\d+\.\d+\.\d+) port (\d+)'
    
    # Check for connection request
    match = re.search(connection_pattern, line)
    if match:
        ip = match.group(1)
        port = match.group(2)
        return {
            'type': 'CONNECTION',
            'ip': ip,
            'port': port
        }
    
    # Check for invalid user
    match = re.search(invalid_user_pattern, line)
    if match:
        username = match.group(1)
        ip = match.group(2)
        return {
            'type': 'INVALID_USER',
            'username': username,
            'ip': ip
        }
    
    # Check for failed attempts
    match = re.search(failed_pattern, line)
    if match:
        username = match.group(1)
        ip = match.group(2)
        port = match.group(3)
        return {
            'type': 'AUTH_FAIL',
            'username': username,
            'ip': ip,
            'port': port,
            'method': 'password'
        }
    
    # Check for successful login
    match = re.search(success_pattern, line)
    if match:
        method = match.group(1)
        username = match.group(2)
        ip = match.group(3)
        port = match.group(4)
        return {
            'type': 'AUTH_SUCCESS',
            'username': username,
            'ip': ip,
            'port': port,
            'method': method
        }
    
    # Check for disconnection
    match = re.search(disconnect_pattern, line)
    if match:
        ip = match.group(1)
        port = match.group(2)
        return {
            'type': 'DISCONNECT',
            'ip': ip,
            'port': port
        }
    
    return None

def check_and_ban():
    """Check failed attempts and ban IPs if threshold exceeded"""
    current_time = time.time()
    
    for ip, attempts in list(failed_attempts.items()):
        # Remove old attempts outside time window
        failed_attempts[ip] = [
            (ts, user) for ts, user in attempts 
            if current_time - ts < TIME_WINDOW
        ]
        
        # Check if IP should be banned
        if len(failed_attempts[ip]) >= MAX_ATTEMPTS and ip not in banned_ips:
            username = failed_attempts[ip][0][1]  # Get username from first attempt
            ban_ip(ip, username, len(failed_attempts[ip]))

def monitor_auth_log():
    """Monitor authentication log for SSH events"""
    log_event("SSH IDPS Started - Monitoring for intrusions...", "INIT")
    load_banned_ips()
    
    # Use journalctl for systemd-based systems (Arch Linux)
    try:
        process = subprocess.Popen(
            ["sudo", "journalctl", "-u", "sshd", "-f", "-n", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        log_event("Monitoring journalctl for SSH events...", "INIT")
        
        for line in process.stdout:
            event = parse_ssh_log_line(line)
            
            if event:
                event_type = event['type']
                ip = event.get('ip')
                
                if event_type == 'CONNECTION':
                    log_event(
                        f"Connection request | IP: {ip} | Port: {event['port']}",
                        "CONNECTION"
                    )
                
                elif event_type == 'INVALID_USER':
                    log_event(
                        f"Invalid user attempt | User: {event['username']} | IP: {ip}",
                        "WARNING"
                    )
                
                elif event_type == 'AUTH_FAIL':
                    timestamp = time.time()
                    username = event['username']
                    failed_attempts[ip].append((timestamp, username))
                    
                    log_event(
                        f"Authentication failed | User: {username} | IP: {ip} | "
                        f"Port: {event['port']} | Method: {event['method']} | "
                        f"Attempt: {len(failed_attempts[ip])}/{MAX_ATTEMPTS}",
                        "AUTH_FAIL"
                    )
                    
                    check_and_ban()
                
                elif event_type == 'AUTH_SUCCESS':
                    username = event['username']
                    log_event(
                        f"Authentication successful | User: {username} | IP: {ip} | "
                        f"Port: {event['port']} | Method: {event['method']}",
                        "AUTH_SUCCESS"
                    )
                    # Clear failed attempts for this IP on successful login
                    if ip in failed_attempts:
                        del failed_attempts[ip]
                
                elif event_type == 'DISCONNECT':
                    log_event(
                        f"Session ended | IP: {ip} | Port: {event['port']}",
                        "DISCONNECT"
                    )
                
    except KeyboardInterrupt:
        log_event("IDPS stopped by user", "SHUTDOWN")
    except Exception as e:
        log_event(f"Error monitoring logs: {e}", "ERROR")

def main():
    """Main function"""
    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        exit(1)
    
    # Create log files if they don't exist
    for log_file in [LIVE_LOG, BANNED_LOG]:
        if not os.path.exists(log_file):
            open(log_file, 'a').close()
    
    monitor_auth_log()

if __name__ == "__main__":
    main()
