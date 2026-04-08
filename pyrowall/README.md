# AKID's Firewall App — Cross-Platform Network Security Tool

**AKID's Firewall App** is a sophisticated, cross-platform network firewall with a beautiful
web-based dashboard. It runs on both **Linux** and **Windows**, inspects network packets in
real-time, enforces configurable rules, and exposes a full control panel at `http://localhost:5000`.

> © 2026 Akid's Global Cyber Security Tools. All rights reserved.

---

## Features

- **Live packet inspection** using Scapy (falls back to simulation mode if unavailable)
- **Rule-based filtering** — by protocol (TCP/UDP/ICMP), port, IP address, CIDR range, direction
- **IP Blacklist** — instantly block any IP with one click
- **Default rules** pre-configured:
  - Block HTTP (port 80)
  - Block ICMP (ping)
  - Allow HTTPS (443), DNS (53), SSH (22), Loopback
- **Real-time dashboard** with live traffic feed, charts, and stats
- **Traffic logs** — searchable, filterable, exportable as CSV
- **Cross-platform** — Linux (iptables) + Windows (netsh advfirewall)
- **Beautiful dark UI** — built with plain HTML/CSS/JS, no framework needed

---

## Requirements

- Python 3.10+
- Linux or Windows
- **Linux**: run as `root` (sudo)
- **Windows**: run as Administrator

---

## Installation

### 1. Clone / download the project

```bash
git clone https://github.com/AKID-S-GLOBAL-INTL-LTD/PROJECTS
cd akid-firewall
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

On Linux you may also need:

```bash
sudo apt install python3-scapy   # optional, pip scapy also works
```

### 3. Run the App

**Linux:**
```bash
sudo python3 main.py
```

**Windows (run terminal as Administrator):**
```cmd
python main.py
```

### 4. Open the dashboard

Open your browser and go to:
```
http://127.0.0.1:5000
```

---

## Dashboard Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Live traffic feed, packet counts, CPU/RAM, charts |
| **Firewall Rules** | Create, edit, toggle, delete rules |
| **IP Blacklist** | Block/unblock specific IP addresses |
| **Traffic Logs** | Full log history with filters and CSV export |
| **Settings** | Toggle engine, logging options, system info |

---

## Default Rules

| Rule | Action | Protocol | Port |
|------|--------|----------|------|
| Allow Loopback | Allow | Any | Any |
| Block HTTP Traffic | **Block** | TCP | 80 |
| Block ICMP (Ping) | **Block** | ICMP | — |
| Allow HTTPS | Allow | TCP | 443 |
| Allow DNS | Allow | UDP | 53 |
| Allow SSH | Allow | TCP | 22 |

Default rules **cannot be deleted** but can be toggled on/off.

---

## Creating Custom Rules

1. Go to **Firewall Rules** in the sidebar
2. Click **+ New Rule**
3. Fill in:
   - **Name** — descriptive label
   - **Action** — Block or Allow
   - **Protocol** — TCP, UDP, ICMP, or Any
   - **Direction** — Inbound, Outbound, or Both
   - **Source/Destination IP** — exact IP, CIDR range, or `any`
   - **Source/Destination Port** — number, range (`1024-2048`), or `any`
   - **Priority** — lower number = evaluated first

---

## IP Blacklisting

- Go to **IP Blacklist** → click **Block IP**
- Enter an IP or CIDR range (e.g. `192.168.1.0/24`)
- Optionally add a reason
- Blacklisted IPs are blocked regardless of any other rules

From the **Dashboard**, click **Block** next to any top offender IP to instantly blacklist it.

---

## Simulation Mode

If Scapy is not installed or the tool is run without root/admin privileges,
the app automatically enters **simulation mode** — it generates synthetic traffic
so you can test all dashboard features without needing real packet capture.

---

## Running Tests

```bash
# Filter logic tests (no DB needed)
python3 tests/test_filter.py

# Database model tests
python3 tests/test_rules.py

# Full API integration tests
python3 tests/test_api.py
```

---

## Project Structure

```
akid-firewall/
├── main.py                    # Entry point
├── config.yaml                # App configuration
├── requirements.txt
├── core/
│   ├── engine.py              # Packet sniffing + processing loop
│   ├── filter.py              # Rule matching logic
│   ├── rules.py               # Default rule definitions
│   └── platform.py            # OS detection
├── db/
│   ├── database.py            # SQLite setup
│   ├── models.py              # Rule, Blacklist, Log, Settings models
│   └── akid_firewall.db       # Auto-created on first run
├── web/
│   ├── app.py                 # Flask factory
│   ├── routes/
│   │   ├── dashboard.py
│   │   ├── rules_api.py
│   │   ├── blacklist_api.py
│   │   ├── logs_api.py
│   │   └── settings_api.py
│   └── templates/
│       └── dashboard.html     # Full SPA dashboard
├── adapters/
│   ├── linux_iptables.py      # iptables wrapper
│   └── windows_wfp.py         # netsh wrapper
└── tests/
    ├── test_filter.py
    ├── test_rules.py
    └── test_api.py
```

---

## REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/rules` | List all rules |
| POST | `/api/rules` | Create a rule |
| PUT | `/api/rules/<id>` | Update a rule |
| DELETE | `/api/rules/<id>` | Delete a rule |
| POST | `/api/rules/<id>/toggle` | Enable/disable a rule |
| GET | `/api/blacklist` | List blacklisted IPs |
| POST | `/api/blacklist` | Add IP to blacklist |
| DELETE | `/api/blacklist/<id>` | Remove IP from blacklist |
| GET | `/api/logs` | Get traffic logs |
| GET | `/api/logs/export` | Export logs as CSV |
| POST | `/api/logs/clear` | Clear all logs |
| GET | `/api/stats` | Traffic statistics |
| GET | `/api/settings` | Get settings |
| POST | `/api/settings` | Update settings |
| GET | `/api/system` | System info (CPU, RAM, interfaces) |

---

## License

© 2026 Akid's Global Cyber Security Tools. All rights reserved.
