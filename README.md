

# 📚 About the Project

ARPShield is a cybersecurity application developed to demonstrate how ARP Spoofing (ARP Poisoning) attacks are performed and how they can be detected in real time within a Local Area Network.

The project combines offensive and defensive security concepts into a single platform. It enables users to scan the local network, simulate ARP spoofing attacks, monitor ARP traffic, detect suspicious activities, log security events, and visualize network status through a modern web dashboard.

This project was developed for academic purposes to provide hands-on understanding of Layer-2 attacks and their mitigation techniques.

---

# 🎯 Project Objectives

- Understand ARP Protocol.
- Demonstrate ARP Spoofing attacks.
- Detect malicious ARP packets.
- Monitor network devices.
- Visualize network topology.
- Generate security alerts.
- Store attack history.
- Build an interactive Flask dashboard.
- Improve practical cybersecurity skills.

---

# ✨ Features

## 🔍 Network Scanner

- Scan all active devices in the connected network
- Detect IP addresses
- Detect MAC addresses
- Identify newly connected hosts
- Live network discovery
- Refresh network scan

---

## 🚨 ARP Attack Detection

- Duplicate IP Detection
- MAC Address Change Detection
- Suspicious ARP Reply Detection
- Gratuitous ARP Detection
- Unknown Device Detection
- Gateway MAC Verification
- Live Packet Monitoring
- Attack Alert Generation

---

## ⚔️ ARP Spoofing Module

- Simulate ARP Poisoning
- Send Fake ARP Replies
- MITM Demonstration
- Continuous ARP Poisoning
- Restore Original ARP Tables
- Configurable Packet Interval

---

## 📊 Dashboard

- Modern Responsive UI
- Device Statistics
- Live Alerts
- Network Status
- Recent Events
- Topology Visualization
- Attack Summary
- Alert Timeline

---

## 💾 Database

- Store Alerts
- Store Network Devices
- Store Event History
- Attack Logs
- Scan History

---

# 🛠️ Technologies Used

| Technology | Purpose |
|------------|----------|
| Python | Core Programming |
| Flask | Web Framework |
| Scapy | Packet Crafting & Sniffing |
| SQLite | Database |
| HTML5 | Frontend |
| CSS3 | Styling |
| JavaScript | Dynamic Dashboard |
| Bootstrap | Responsive Design |

---

# 🏗️ System Architecture

```
                    +-----------------------+
                    |     Local Network     |
                    +-----------+-----------+
                                |
                         ARP Broadcast Traffic
                                |
             +------------------+------------------+
             |                                     |
      Network Scanner                    ARP Monitor
             |                                     |
      Host Discovery                   Packet Analysis
             |                                     |
      Device Information            Attack Detection Engine
             |                                     |
             +------------------+------------------+
                                |
                         SQLite Database
                                |
                         Flask Web Server
                                |
                         Web Dashboard UI
```

---

# 📂 Project Structure

```
ARPShield/
│
├── app.py
├── arp_monitor.py
├── arp_spoofer.py
├── database.py
├── models.py
├── requirements.txt
│
├── templates/
│   ├── index.html
│   ├── dashboard.html
│   └── ...
│
├── static/
│   ├── css/
│   ├── js/
│   ├── images/
│   └── icons/
│
├── screenshots/
│
├── database/
│   └── arp.db
│
└── README.md
```

---

# 💻 System Requirements

## Hardware

- Intel i3 Processor or Above
- 4 GB RAM (8 GB Recommended)
- 500 MB Free Storage

---

## Software

- Python 3.10+
- Flask
- Scapy
- SQLite
- Npcap (Windows)
- VS Code / PyCharm

---

# 📥 Installation

Clone Repository

```bash
git clone https://github.com/USERNAME/ARPShield.git
```

Move to project

```bash
cd ARPShield
```

Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 📦 Required Python Packages

```text
Flask
Scapy
Flask_SQLAlchemy
SQLAlchemy
psutil
requests
netifaces
colorama
```

---

# ▶️ Running the Project

Start Dashboard

```bash
python app.py
```

Start ARP Monitor

```bash
python arp_monitor.py
```

Run ARP Spoofer

```bash
python arp_spoofer.py
```

Open Browser

```
http://127.0.0.1:5000
```

---

# 📊 Dashboard Features

- Live Network Statistics
- Connected Devices
- Active Alerts
- Threat Level
- Network Topology
- Recent Logs
- Packet Information
- Attack Timeline

---

# 🔍 Modules

## 1. Network Scanner

Responsible for discovering all active hosts in the network.

Functions

- Scan Network
- Identify Devices
- Store Results

---

## 2. ARP Spoofer

Responsible for attack simulation.

Functions

- Send Forged ARP Replies
- Poison Victim Cache
- Restore Network

---

## 3. ARP Monitor

Responsible for security monitoring.

Functions

- Sniff ARP Packets
- Detect Spoofing
- Generate Alerts

---

## 4. Dashboard

Responsible for visualization.

Functions

- Display Alerts
- Device Monitoring
- Statistics
- Event History

---

# 🔄 Project Workflow

```
Start Application
        │
        ▼
Scan Local Network
        │
        ▼
Identify Devices
        │
        ▼
Monitor ARP Traffic
        │
        ▼
Detect Suspicious Activity
        │
        ▼
Generate Alerts
        │
        ▼
Store in Database
        │
        ▼
Display on Dashboard
```

---

# 🗄️ Database

The SQLite database stores:

- Device Information
- Alert History
- Network Events
- Attack Logs
- MAC Address Records

---

# 📸 Screenshots

Create a folder named **screenshots**

Example

```
screenshots/

dashboard.png

scanner.png

alerts.png

network.png

topology.png
```

Display Images

```markdown
## Dashboard

![Dashboard](screenshots/dashboard.png)

## Scanner

![Scanner](screenshots/scanner.png)

## Alerts

![Alerts](screenshots/alerts.png)
```

---

# 🧪 Testing

The application has been tested for

- Network Discovery
- ARP Detection
- Packet Monitoring
- Database Logging
- Dashboard Updates
- Alert Generation

---

# 🚀 Future Enhancements

- Machine Learning Detection
- Docker Support
- Email Alerts
- Telegram Notifications
- Cloud Dashboard
- REST API
- Authentication
- Role Based Access
- Packet Capture Export
- SIEM Integration

---




# 📖 References

- RFC 826 — Address Resolution Protocol
- Scapy Documentation
- Flask Documentation
- SQLite Documentation
- Python Documentation
- SANS Institute Research Papers
- OWASP Network Security Guidelines

---

# ⚠️ Disclaimer

This software has been developed **strictly for educational and research purposes**.

Do not use this tool against networks or systems without explicit authorization.

The authors are not responsible for any misuse of this project.

---

# 📜 License

This project is licensed under the **MIT License**.

---

# 🙏 Acknowledgements

We sincerely thank:

- Lovely Professional University
- Department of Computer Applications
- Faculty Members
- Open Source Community
- Python Developers
- Flask Community
- Scapy Developers
- Cybersecurity Research Community

---

# 🌟 Support

If you found this project useful:

⭐ Star this repository

🍴 Fork this repository

🐛 Report Issues

💡 Suggest Improvements

---

## 📬 Contact

**Rahul Kumar**

MCA (Hons.) Cyber Security

Lovely Professional University

GitHub: https://github.com/chahar01

Email: rahulsingh25chahar@gmail.com

---

# ❤️ Made with Python, Flask, Scapy & Cybersecurity Passion by Team ARPShield
