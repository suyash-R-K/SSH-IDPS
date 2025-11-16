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
- [Screenshots](#screenshots)
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

-  Real-time SSH connection monitoring
-  Complete connection lifecycle tracking (connection → authentication → disconnect)
-  Automatic IP banning after configurable failed attempts (default: 5)
-  Time-window based detection (5-minute sliding window)
-  Dual logging system (live log + banned IP registry)
-  Invalid user detection and logging
-  Authentication method tracking (password/publickey)
-  Source port and session tracking
-  Persistent ban list across system restarts
-  Detailed forensic logging with timestamps

-  ## Lab Environment

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

