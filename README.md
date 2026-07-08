# ARP Spoofing Attack & Detection Tool

## Overview
A professional-grade tool demonstrating ARP cache poisoning (MITM) and real-time detection. It includes:
- **ARP Spoofer** – forges ARP replies, enables IP forwarding, and restores ARP tables.
- **ARP Monitor** – detects MAC changes, duplicate IPs, unsolicited replies, excessive traffic, and gateway MAC changes.
- **Flask Dashboard** – full control, live visualization, network topology, event log, charts, and export.
- **SQLite** – persistent event storage.

## Features
- Network scanner (ARP discovery)
- Live topology graph (attack vs. normal)
- Statistics cards
- CSV export
- Educational section on ARP, detection, and DAI
- IP forwarding (Windows/Linux) for true MITM

## Setup
1. Install Python 3.6+ and dependencies:
   ```bash
   pip install -r requirements.txt