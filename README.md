# SSH Intrusion Detection & Prevention System (IDPS)

A Python-based real-time SSH monitoring system that detects brute-force attacks and automatically blocks malicious IPs using iptables.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Lab Environment](#lab-environment)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Log Examples](#log-examples)
- [Unbanning IPs](#unbanning-ips)
- [How It Works](#how-it-works)
- [Learning Outcomes](#learning-outcomes)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

This project demonstrates a practical implementation of an Intrusion Detection and Prevention System (IDPS) for SSH services. It monitors authentication logs in real-time, tracks failed login attempts, and automatically bans IP addresses that exceed the configured threshold using iptables firewall rules.

The system provides complete visibility into SSH connection lifecycle - from initial connection requests through authentication attempts to session termination - making it an effective tool for detecting and preventing brute-force attacks.

## Features

- Real-time SSH connection monitoring
- Complete connection lifecycle tracking (connection → authentication → disconnect)
- Automatic IP banning after configurable failed attempts (default: 5)
- Time-window based detection (5-minute sliding window)
- Dual logging system (live log + banned IP registry)
- Invalid user detection and logging
- Authentication method tracking (password/publickey)
- Source port and session tracking
- Persistent ban list across system restarts
- Detailed forensic logging with timestamps

## Lab Environment

**Components:**
- **SSH Host (Defender):** Arch Linux with Python 3, iptables, and OpenSSH
- **Attack Client:** Kali Linux with Hydra brute-force tool

**Network:**
- Local network setup (192.168.x.x)
- SSH service running on port 22

**Tools Used:**
- Python 3 (monitoring script)
- iptables (firewall management)
- journalctl (system log monitoring)
- Hydra (attack simulation)

<<<<<<< HEAD
## Installation

### Prerequisites
```bash
# On Arch Linux (SSH Host)
sudo pacman -S python3 iptables openssh

# Ensure SSH service is running
sudo systemctl start sshd
sudo systemctl enable sshd
sudo systemctl status sshd
```

### Setup
```bash
# Clone the repository
git clone https://github.com/suyash-R-K/SSH-IDPS.git
cd SSH-IDPS
=======
##  Lab Environment

- **SSH Host (Defender):** Arch Linux
- **Attack Simulation:** Kali Linux with Hydra
- **Network:** Local network (192.168.0.117)

---

##  Prerequisites

### Required Software
- **Python 3.x** - For running the monitoring script
- **iptables** - For firewall management
- **SSH Server** - OpenSSH or equivalent
- **systemd/journalctl** - For log monitoring (or traditional syslog)

### Required Permissions
- Root or sudo access for iptables management
- Access to authentication logs (/var/log/auth.log or journalctl)

### Installation Commands

**On Arch Linux:**
```bash
sudo pacman -S python3 iptables openssh
```

**On Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 iptables openssh-server
```

**On CentOS/RHEL:**
```bash
sudo yum install python3 iptables openssh-server
```

### Verify SSH Service
```bash
# Start SSH service
sudo systemctl start sshd

# Enable on boot
sudo systemctl enable sshd

# Check status
sudo systemctl status sshd
```
### Setup
```bash
# Clone the repository
git clone https://github.com/suyash-R-K/SSH-IDPS.git
cd SSH-IDPS
>>>>>>> 52b95212e6b19212dbb9ef740f255bedcbbb7c14

# Make script executable
chmod +x ssh_idps.py

# Run the IDPS (requires root privileges)
sudo python3 ssh_idps.py
```

## Configuration

Edit `ssh_idps.py` to customize behavior:
```python
MAX_ATTEMPTS = 5        # Number of failed attempts before ban
TIME_WINDOW = 300       # Time window in seconds (5 minutes)
LIVE_LOG = "idps_live_log.txt"      # Live event log file
BANNED_LOG = "banned_ips.txt"       # Banned IPs registry
CHECK_INTERVAL = 2      # Log check interval in seconds
```
<<<<<<< HEAD

## Usage

### Starting the IDPS
```bash
# Terminal 1: Start the monitoring system
sudo python3 ssh_idps.py
```

### Monitoring in Real-Time
```bash
# Terminal 2: Watch live logs
tail -f idps_live_log.txt

# Terminal 3: Monitor iptables rules
watch -n 1 'sudo iptables -L INPUT -v -n'

# Terminal 4: Check banned IPs
cat banned_ips.txt
```

### Stopping the IDPS

Press `Ctrl+C` in the terminal running the script to stop monitoring gracefully.

## Testing

### Attack Simulation from Kali Linux
```bash
# Create a password wordlist
echo -e "wrong1\nwrong2\nwrong3\nwrong4\nwrong5\nwrong6" > passwords.txt

# Launch SSH brute-force attack
hydra -l testuser -P passwords.txt ssh://TARGET_IP -t 4 -V

# Or use a larger wordlist
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP -t 4
```

### Defense Monitoring on Arch Linux
```bash
# Watch the IDPS detect and ban the attacker
# You should see:
# 1. Connection requests
# 2. Failed authentication attempts (1/5, 2/5, 3/5, 4/5, 5/5)
# 3. IP banned message
# 4. iptables rule added
```

### Verify Ban is Active
```bash
# Check iptables rules
sudo iptables -L INPUT -v -n | grep DROP

# Try to connect from Kali (should timeout)
ssh testuser@TARGET_IP
```

## Log Examples

### Connection Request
```
[2024-11-09 10:30:20] [CONNECTION] Connection request | IP: 192.168.0.105 | Port: 54321
```

### Failed Authentication
```
[2024-11-09 10:30:21] [AUTH_FAIL] Authentication failed | User: testuser | IP: 192.168.0.105 | Port: 54321 | Method: password | Attempt: 1/5
```

### Successful Login
```
[2024-11-09 10:35:01] [AUTH_SUCCESS] Authentication successful | User: testuser | IP: 192.168.0.117 | Port: 60123 | Method: password
```

### Invalid User Attempt
```
[2024-11-09 10:30:22] [WARNING] Invalid user attempt | User: admin | IP: 192.168.0.105
```

### IP Banned
```
[2024-11-09 10:30:29] [SECURITY] IP BANNED | IP: 192.168.0.105 | User: testuser | Total attempts: 5 | Reason: Brute force detected
```

### Session Disconnected
```
[2024-11-09 10:45:00] [DISCONNECT] Session ended | IP: 192.168.0.117 | Port: 60123
```

### Complete Attack Timeline Example
```
[2024-11-09 10:30:15] [INIT] SSH IDPS Started - Monitoring for intrusions...
[2024-11-09 10:30:20] [CONNECTION] Connection request | IP: 192.168.0.105 | Port: 54321
[2024-11-09 10:30:21] [AUTH_FAIL] Authentication failed | User: testuser | IP: 192.168.0.105 | Port: 54321 | Method: password | Attempt: 1/5
[2024-11-09 10:30:22] [CONNECTION] Connection request | IP: 192.168.0.105 | Port: 54322
[2024-11-09 10:30:23] [AUTH_FAIL] Authentication failed | User: testuser | IP: 192.168.0.105 | Port: 54322 | Method: password | Attempt: 2/5
[2024-11-09 10:30:24] [CONNECTION] Connection request | IP: 192.168.0.105 | Port: 54323
[2024-11-09 10:30:25] [AUTH_FAIL] Authentication failed | User: admin | IP: 192.168.0.105 | Port: 54323 | Method: password | Attempt: 3/5
[2024-11-09 10:30:26] [CONNECTION] Connection request | IP: 192.168.0.105 | Port: 54324
[2024-11-09 10:30:27] [AUTH_FAIL] Authentication failed | User: root | IP: 192.168.0.105 | Port: 54324 | Method: password | Attempt: 4/5
[2024-11-09 10:30:28] [CONNECTION] Connection request | IP: 192.168.0.105 | Port: 54325
[2024-11-09 10:30:29] [AUTH_FAIL] Authentication failed | User: testuser | IP: 192.168.0.105 | Port: 54325 | Method: password | Attempt: 5/5
[2024-11-09 10:30:29] [SECURITY] IP BANNED | IP: 192.168.0.105 | User: testuser | Total attempts: 5 | Reason: Brute force detected
```

## Unbanning IPs

### Method 1: Manual iptables Command
```bash
# Unban a specific IP
sudo iptables -D INPUT -s 192.168.0.105 -j DROP

# List all banned IPs
sudo iptables -L INPUT -v -n | grep DROP

# Clear all INPUT rules (use with caution)
sudo iptables -F INPUT
```

### Method 2: Unban Utility (if available)
```bash
# Interactive mode
sudo python3 unban_utility.py

# Unban specific IP
sudo python3 unban_utility.py 192.168.0.105

# List all banned IPs
sudo python3 unban_utility.py --list

# Unban all IPs
sudo python3 unban_utility.py --all
```

### Verifying Unban
```bash
# Check iptables rules are removed
sudo iptables -L INPUT -v -n

# Test connection from previously banned IP
ssh testuser@TARGET_IP
```

## How It Works

### 1. Detection Phase
- Monitors `journalctl` output for SSH-related events in real-time
- Parses log entries using regex patterns to extract:
  - Connection requests
  - Authentication attempts (success/failure)
  - Invalid user attempts
  - Session disconnections
- Tracks failed attempts per IP address with timestamps

### 2. Analysis Phase
- Maintains a sliding time window (default: 5 minutes)
- Counts failed authentication attempts within the time window
- Removes expired attempts outside the time window
- Identifies IPs exceeding the threshold (default: 5 attempts)

### 3. Prevention Phase
- Automatically triggers ban when threshold is reached
- Adds iptables DROP rule to block all traffic from the IP
- Records ban details to persistent log file
- Continues monitoring for new threats

### 4. Logging Phase
- Records all events with precise timestamps
- Categorizes events by type (CONNECTION, AUTH_FAIL, AUTH_SUCCESS, SECURITY, etc.)
- Maintains two log files:
  - `idps_live_log.txt` - Real-time event log
  - `banned_ips.txt` - Registry of banned IPs
- Provides complete audit trail for forensic analysis

### Architecture Diagram
```
┌─────────────────┐         ┌──────────────────┐
│   SSH Client    │────────▶│   SSH Server     │
│  (Kali Linux)   │         │  (Arch Linux)    │
└─────────────────┘         └──────────────────┘
                                      │
                                      ▼
                            ┌──────────────────┐
                            │   journalctl     │
                            │  (System Logs)   │
                            └──────────────────┘
                                      │
                                      ▼
                            ┌──────────────────┐
                            │   IDPS Script    │
                            │  (ssh_idps.py)   │
                            └──────────────────┘
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                  ┌─────────────┐          ┌─────────────┐
                  │  iptables   │          │  Log Files  │
                  │  (Firewall) │          │             │
                  └─────────────┘          └─────────────┘
```

## Learning Outcomes

This project demonstrates practical skills in:

**Cybersecurity:**
- Real-time intrusion detection techniques
- Brute-force attack recognition and mitigation
- Network security fundamentals
- Incident response automation
- Security event logging and forensics

**Linux System Administration:**
- iptables firewall configuration and management
- systemd journal monitoring with journalctl
- SSH server configuration and hardening
- Process management and monitoring

**Python Programming:**
- Real-time log parsing and analysis
- Regular expression pattern matching
- Subprocess management and system integration
- Data structures for tracking and analysis
- Error handling and logging

**Ethical Hacking:**
- Attack simulation methodologies
- Password-based brute-force techniques
- Security testing best practices
- Responsible disclosure principles

## Disclaimer

**This project is for educational and research purposes only.**

- Only test on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal under various laws including the Computer Fraud and Abuse Act (CFAA)
- The author is not responsible for any misuse or damage caused by this software
- Always follow responsible disclosure practices
- Respect privacy and data protection laws
- Use this knowledge to improve security, not to cause harm

By using this software, you agree to use it responsibly and ethically.

## License

This project is open source and available under the MIT License.
```
MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```


If you found this project helpful, please consider giving it a star!
=======
>>>>>>> 52b95212e6b19212dbb9ef740f255bedcbbb7c14
