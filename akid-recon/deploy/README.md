# 🛡️ AKID's Recon Automation Tool
### Akids Global CyberSecurity Tools © 2026

A professional web-based reconnaissance automation platform. Enter any domain and get a complete, copy-paste-ready set of commands covering every stage of the recon workflow — from passive OSINT to active vulnerability scanning.

---

## Features

- **14 Recon Sections** — 80+ tools and commands auto-generated per domain
- **Passive + Active** recon clearly separated and filterable
- **One-click copy** per command, per tool, or all at once
- **User accounts** — register, login, scan history
- **Scan history** — every scan saved, searchable, re-runnable
- **Dark cyberpunk UI** built for security professionals

---

## Recon Sections Generated

| # | Section | Type | Key Tools |
|---|---------|------|-----------|
| 1 | Initial Setup | — | mkdir workspace |
| 2 | Subdomain Enumeration | Passive | Subfinder, Amass, Assetfinder, Findomain, crt.sh, Knockpy, dnsx, gotator |
| 3 | DNS Reconnaissance | Passive | host, dig, dnsrecon, dnsenum, fierce, SPF/DMARC checks, hakrevdns |
| 4 | HTTP Probing | Active | httpx, httprobe |
| 5 | Port Scanning | Active | Nmap (quick/full/vuln/UDP), Masscan, RustScan |
| 6 | Technology Fingerprinting | Passive | WhatWeb, wafw00f, CMSeeK, Nikto, testssl |
| 7 | Web Archives | Passive | waybackurls, gau, waymore, unfurl, URLScan.io |
| 8 | Directory Bruteforcing | Active | ffuf, Gobuster, dirsearch, feroxbuster |
| 9 | JavaScript Analysis | Passive | getJS, subjs, LinkFinder, SecretFinder, grep |
| 10 | Google Dorks & OSINT | Passive | theHarvester, h8mail, curated dork queries |
| 11 | Screenshot & Visual Recon | Active | gowitness, aquatone, EyeWitness |
| 12 | Vulnerability Scanning | Active | Nuclei (7000+ templates), Nikto, subjack, CORScanner |
| 13 | Cloud & Asset Discovery | Passive | S3Scanner, cloud_enum, Shodan CLI, Censys CLI |
| 14 | Consolidate & Report | — | Summary stats, tar archive |

---

## Tech Stack

- **Backend**: Python 3 / Flask / SQLAlchemy / JWT
- **Frontend**: Vanilla HTML/CSS/JS (no frameworks)
- **Database**: SQLite (dev) / PostgreSQL (prod)
- **Server**: Gunicorn + Nginx
- **OS**: Ubuntu 24.04 LTS

---

## Quick Deploy on Ubuntu 24.04 EC2

### 1. Clone / upload the project
```bash
git clone https://github.com/yourrepo/akid-recon.git ~/akid-recon
# OR upload via scp:
# scp -r akid-recon/ ubuntu@YOUR_EC2_IP:~/
```

### 2. Run the setup script
```bash
cd ~/akid-recon/deploy
chmod +x setup.sh
./setup.sh
```

The script will:
- Install Python 3, pip, Nginx
- Create a virtual environment and install dependencies
- Generate random JWT and app secrets in `.env`
- Initialize the SQLite database
- Install and start the `akid-recon` systemd service
- Configure and reload Nginx

### 3. Open in browser
```
http://YOUR_EC2_PUBLIC_IP
```

---

## Manual Setup (Step by Step)

```bash
# 1. Install system deps
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nginx

# 2. Backend setup
cd ~/akid-recon/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Environment
cat > .env <<EOF
SECRET_KEY=your-random-secret
JWT_SECRET_KEY=your-jwt-secret
DATABASE_URL=sqlite:///akid_recon.db
EOF

# 4. Init DB
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"

# 5. Test run
python3 app.py
# Visit: http://localhost:5000

# 6. Gunicorn (production)
gunicorn -w 4 -b 127.0.0.1:5000 app:app

# 7. Nginx
sudo cp ~/akid-recon/deploy/nginx.conf /etc/nginx/sites-available/akid-recon
sudo ln -s /etc/nginx/sites-available/akid-recon /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 8. Systemd service
sudo cp ~/akid-recon/deploy/akid-recon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now akid-recon
```

---

## EC2 Security Group Settings

Make sure your EC2 security group allows:

| Type | Port | Source |
|------|------|--------|
| SSH | 22 | Your IP |
| HTTP | 80 | 0.0.0.0/0 |
| HTTPS | 443 | 0.0.0.0/0 |

---

## HTTPS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

## Service Management

```bash
# Status
sudo systemctl status akid-recon

# Logs (live)
sudo journalctl -u akid-recon -f

# Restart
sudo systemctl restart akid-recon

# Stop
sudo systemctl stop akid-recon
```

---

## Project Structure

```
akid-recon/
├── backend/
│   ├── app.py           # Flask app entry point
│   ├── models.py        # User + ScanHistory models
│   ├── auth.py          # Register/login/JWT
│   ├── history.py       # Scan history CRUD
│   ├── commands.py      # All recon command generators
│   └── requirements.txt
├── frontend/
│   ├── index.html       # Login/register page
│   ├── dashboard.html   # Main tool interface
│   └── history.html     # Scan history page
└── deploy/
    ├── setup.sh         # One-command installer
    ├── nginx.conf       # Nginx config
    ├── akid-recon.service  # Systemd unit
    └── README.md
```

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Only use it against systems you own or have explicit written permission to test. Unauthorized use may violate computer fraud laws. Akids Global CyberSecurity Tools and the author accept no liability for misuse.

---

*AKID's Recon Automation Tool — Akids Global CyberSecurity Tools © 2026*
