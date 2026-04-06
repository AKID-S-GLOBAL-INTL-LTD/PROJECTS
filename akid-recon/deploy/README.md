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

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Only use it against systems you own or have explicit written permission to test. Unauthorized use may violate computer fraud laws. Akids Global CyberSecurity Tools and the author accept no liability for misuse.

---

*AKID's Recon Automation Tool — Akids Global CyberSecurity Tools © 2026*
