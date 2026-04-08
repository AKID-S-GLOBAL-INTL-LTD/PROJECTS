# SubDiscover v2.0
### Akid's Global Cyber Security Tools © 2026

Advanced subdomain and asset discovery engine written in Go.

## Features

- **Multi-source subdomain collection**
  - DNS bruteforce with built-in 180+ word wordlist (or custom)
  - Certificate Transparency logs (crt.sh)
  - OSINT: HackerTarget, AlienVault OTX passive DNS
- **Smart DNS resolution**
  - Concurrent A/AAAA/CNAME resolution
  - CDN detection (Cloudflare, Akamai, Fastly, CloudFront, etc.)
  - Multiple upstream resolvers with retry logic
  - Result caching
- **DNS Asset Enumeration**
  - MX, NS, TXT, SOA records for the root domain
  - SPF/DMARC detection via TXT parsing
- **HTTP/HTTPS Probing**
  - HTTPS-first probing with fallback to HTTP
  - Title extraction
  - Technology fingerprinting (CMS, frameworks, servers)
  - Redirect tracking
- **Interactive Terminal Mode**
  - Guided setup when run without flags
- **Rich Terminal Output**
  - Colored, structured display with progress bars
  - Section headers, stats summary, branded footer
- **Multiple Output Formats**
  - JSON (structured), TXT (plain list), Markdown (report)

## Installation

```bash
git clone https://github.com/AKID-S-GLOBAL-INTL-LTD/PROJECTS
cd subdiscover
go mod tidy
go build -o subdiscover ./cmd/subdiscover
```

## Usage

### Interactive Mode (no flags)
```bash
./subdiscover
```

### CLI Mode
```bash
./subdiscover -d example.com --http --osint -o report.json
./subdiscover -d example.com -t 100 --http -f md -o report.md
./subdiscover -d example.com -w /path/to/wordlist.txt --no-ct
```

### All Flags
| Flag | Default | Description |
|------|---------|-------------|
| `-d, --domain` | required | Target domain |
| `-t, --threads` | 50 | Concurrent workers |
| `-o, --output` | (none) | Output file path |
| `-f, --format` | json | Output format: json / txt / md |
| `-w, --wordlist` | built-in | Custom wordlist path |
| `--timeout` | 3 | DNS timeout (seconds) |
| `--http` | off | Enable HTTP probing |
| `--osint` | off | Enable OSINT sources |
| `--no-ct` | (CT on) | Disable CT log lookup |
| `--no-assets` | (assets on) | Disable DNS asset enum |
| `-v, --verbose` | off | Verbose output |

## Legal Disclaimer

This tool is intended for authorized security testing only.
Always ensure you have permission before scanning any domain.

---
*Akid's Global Cyber Security Tools © 2026 — All Rights Reserved*
