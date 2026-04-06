def generate_commands(domain):
    d = domain
    d_safe = d.replace('.', '_').replace('-', '_')
    out = f"~/recon/{d}"

    sections = []

    # ─── 1. INITIAL SETUP ───────────────────────────────────────────────────
    sections.append({
        "id": "setup",
        "title": "Initial Setup",
        "icon": "🗂️",
        "description": "Create a clean workspace directory for all recon output files.",
        "passive": True,
        "tools": [
            {
                "tool": "mkdir",
                "description": "Create recon output directory for this target",
                "commands": [
                    f"mkdir -p ~/recon/{d}/{{subdomains,ports,dns,web,js,dirs,screenshots,vulns,osint,archives}}",
                    f"cd ~/recon/{d}",
                    f"echo '[*] Recon workspace ready for {d}'"
                ]
            }
        ]
    })

    # ─── 2. SUBDOMAIN ENUMERATION ───────────────────────────────────────────
    sections.append({
        "id": "subdomains",
        "title": "Subdomain Enumeration",
        "icon": "🔍",
        "description": "Discover subdomains using passive and active techniques. Passive tools query public databases without touching the target. Active tools perform DNS resolution and brute-forcing.",
        "passive": True,
        "tools": [
            {
                "tool": "Subfinder",
                "description": "Fast passive subdomain discovery using 40+ public sources (VirusTotal, Shodan, CertSH, etc.)",
                "commands": [
                    f"subfinder -d {d} -all -recursive -o {out}/subdomains/subfinder.txt",
                    f"echo '[+] Subfinder done:' $(wc -l < {out}/subdomains/subfinder.txt) 'subdomains'"
                ]
            },
            {
                "tool": "Amass (Passive)",
                "description": "OWASP Amass passive mode — DNS enumeration with certificate transparency and scrapers",
                "commands": [
                    f"amass enum -passive -d {d} -o {out}/subdomains/amass_passive.txt",
                    f"echo '[+] Amass passive done'"
                ]
            },
            {
                "tool": "Amass (Active)",
                "description": "OWASP Amass active mode — performs DNS zone transfers, brute-forcing, and permutation scanning",
                "commands": [
                    f"amass enum -active -d {d} -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -o {out}/subdomains/amass_active.txt",
                    f"echo '[+] Amass active done'"
                ]
            },
            {
                "tool": "Assetfinder",
                "description": "Tomnomnom's fast subdomain finder using crt.sh, HackerTarget, Wayback, and more",
                "commands": [
                    f"assetfinder --subs-only {d} | tee {out}/subdomains/assetfinder.txt",
                    f"echo '[+] Assetfinder done'"
                ]
            },
            {
                "tool": "Findomain",
                "description": "Cross-platform subdomain enumerator using certificate transparency logs",
                "commands": [
                    f"findomain -t {d} -u {out}/subdomains/findomain.txt",
                    f"echo '[+] Findomain done'"
                ]
            },
            {
                "tool": "crt.sh",
                "description": "Query certificate transparency logs directly via crt.sh API",
                "commands": [
                    f"curl -s 'https://crt.sh/?q=%25.{d}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u | tee {out}/subdomains/crtsh.txt",
                    f"echo '[+] crt.sh done'"
                ]
            },
            {
                "tool": "Knockpy",
                "description": "Python-based subdomain scanner using wordlists and DNS resolution",
                "commands": [
                    f"knockpy {d} --save {out}/subdomains/knockpy.txt",
                ]
            },
            {
                "tool": "Merge & Deduplicate",
                "description": "Combine all subdomain results into a single clean, deduplicated master list",
                "commands": [
                    f"cat {out}/subdomains/*.txt | sort -u | grep -v '^\\*' | tee {out}/subdomains/all_subdomains.txt",
                    f"echo '[+] Total unique subdomains:' $(wc -l < {out}/subdomains/all_subdomains.txt)"
                ]
            },
            {
                "tool": "dnsx (DNS Probe)",
                "description": "Resolve all discovered subdomains — filters out dead/unresolvable hosts",
                "commands": [
                    f"dnsx -l {out}/subdomains/all_subdomains.txt -resp -o {out}/subdomains/resolved.txt",
                    f"echo '[+] Live resolved subdomains:' $(wc -l < {out}/subdomains/resolved.txt)"
                ]
            },
            {
                "tool": "Permutation Scanning (gotator)",
                "description": "Generate and resolve subdomain permutations to find hidden assets",
                "commands": [
                    f"gotator -sub {out}/subdomains/resolved.txt -perm /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -depth 1 -numbers 3 -md | dnsx -silent -o {out}/subdomains/permutations.txt",
                    f"cat {out}/subdomains/permutations.txt >> {out}/subdomains/resolved.txt && sort -u -o {out}/subdomains/resolved.txt {out}/subdomains/resolved.txt"
                ]
            }
        ]
    })

    # ─── 3. DNS RECONNAISSANCE ──────────────────────────────────────────────
    sections.append({
        "id": "dns",
        "title": "DNS Reconnaissance",
        "icon": "🌐",
        "description": "Deep DNS analysis: A/MX/TXT/NS records, zone transfer attempts, SPF/DMARC checks, and reverse lookups.",
        "passive": True,
        "tools": [
            {
                "tool": "host",
                "description": "Quick DNS lookup — resolves A, MX, and NS records",
                "commands": [
                    f"host {d} | tee {out}/dns/host_{d_safe}.txt",
                    f"host -t mx {d} | tee -a {out}/dns/host_{d_safe}.txt",
                    f"host -t ns {d} | tee -a {out}/dns/host_{d_safe}.txt",
                    f"host -t txt {d} | tee -a {out}/dns/host_{d_safe}.txt"
                ]
            },
            {
                "tool": "dig",
                "description": "Comprehensive DNS interrogation — full record types including ANY, SOA, AXFR zone transfer attempt",
                "commands": [
                    f"dig {d} ANY +noall +answer | tee {out}/dns/dig_any.txt",
                    f"dig {d} MX +short | tee {out}/dns/dig_mx.txt",
                    f"dig {d} NS +short | tee {out}/dns/dig_ns.txt",
                    f"dig {d} TXT +short | tee {out}/dns/dig_txt.txt",
                    f"dig {d} SOA +short | tee {out}/dns/dig_soa.txt",
                    f"dig axfr @$(dig {d} NS +short | head -1) {d} | tee {out}/dns/zone_transfer.txt"
                ]
            },
            {
                "tool": "dnsrecon",
                "description": "Multi-mode DNS recon: std, brute, zone transfer, reverse, SRV, Google enum",
                "commands": [
                    f"dnsrecon -d {d} -t std,axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o {out}/dns/dnsrecon.xml",
                    f"echo '[+] dnsrecon done'"
                ]
            },
            {
                "tool": "dnsenum",
                "description": "Attempts zone transfers, performs Google scraping, brute-forces subdomains",
                "commands": [
                    f"dnsenum --nocolor -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --dnsserver 8.8.8.8 {d} | tee {out}/dns/dnsenum.txt"
                ]
            },
            {
                "tool": "fierce",
                "description": "DNS scanner to locate non-contiguous IP space and hostnames against a target",
                "commands": [
                    f"fierce --domain {d} | tee {out}/dns/fierce.txt"
                ]
            },
            {
                "tool": "SPF / DMARC / DKIM",
                "description": "Check email security records — useful for phishing assessment and email spoofing",
                "commands": [
                    f"dig TXT {d} | grep -E 'spf|dmarc' | tee {out}/dns/email_security.txt",
                    f"dig TXT _dmarc.{d} +short | tee -a {out}/dns/email_security.txt",
                    f"dig TXT default._domainkey.{d} +short | tee -a {out}/dns/email_security.txt"
                ]
            },
            {
                "tool": "Reverse IP Lookup (hakrevdns)",
                "description": "Reverse DNS lookup on all resolved IPs to find other domains on the same server",
                "commands": [
                    f"cat {out}/subdomains/resolved.txt | dnsx -resp-only | sort -u | hakrevdns | tee {out}/dns/reverse_dns.txt"
                ]
            }
        ]
    })

    # ─── 4. HTTP PROBING & LIVE HOST DISCOVERY ──────────────────────────────
    sections.append({
        "id": "httpprobe",
        "title": "HTTP Probing & Live Host Discovery",
        "icon": "📡",
        "description": "Identify which subdomains are running HTTP/HTTPS services, capture status codes, titles, and technologies.",
        "passive": False,
        "tools": [
            {
                "tool": "httpx",
                "description": "Fast multi-purpose HTTP toolkit — probes for live hosts, status codes, titles, TLS, CDN, and tech stack",
                "commands": [
                    f"httpx -l {out}/subdomains/resolved.txt -title -status-code -tech-detect -cdn -ip -follow-redirects -o {out}/web/httpx_live.txt",
                    f"echo '[+] Live web hosts:' $(wc -l < {out}/web/httpx_live.txt)"
                ]
            },
            {
                "tool": "httprobe",
                "description": "Tomnomnom's minimal HTTP prober — quickly checks HTTP/HTTPS on common ports",
                "commands": [
                    f"cat {out}/subdomains/resolved.txt | httprobe -c 50 | tee {out}/web/httprobe_live.txt",
                    f"echo '[+] httprobe live:' $(wc -l < {out}/web/httprobe_live.txt)"
                ]
            },
            {
                "tool": "httpx (Detailed per host)",
                "description": "Extract full details from live hosts: content-length, server headers, CSP, CORS, X-Frame",
                "commands": [
                    f"httpx -l {out}/web/httprobe_live.txt -status-code -content-length -content-type -location -server -x-powered-by -method GET -o {out}/web/httpx_detailed.txt"
                ]
            }
        ]
    })

    # ─── 5. PORT SCANNING ───────────────────────────────────────────────────
    sections.append({
        "id": "ports",
        "title": "Port Scanning",
        "icon": "🔌",
        "description": "Identify open ports and services. Start with fast passive-style scans then escalate to aggressive service/version detection.",
        "passive": False,
        "tools": [
            {
                "tool": "Nmap (Quick SYN scan)",
                "description": "Fast SYN scan on top 1000 ports — good starting point, minimal noise",
                "commands": [
                    f"nmap -sS -T4 --top-ports 1000 {d} -oN {out}/ports/nmap_quick.txt",
                    f"echo '[+] Quick nmap done'"
                ]
            },
            {
                "tool": "Nmap (Full port scan)",
                "description": "Exhaustive scan of all 65535 ports — catches non-standard services",
                "commands": [
                    f"nmap -sS -T4 -p- {d} -oN {out}/ports/nmap_full.txt",
                    f"echo '[+] Full port nmap done'"
                ]
            },
            {
                "tool": "Nmap (Service + Version)",
                "description": "Version detection and default NSE scripts on discovered open ports",
                "commands": [
                    f"nmap -sV -sC -O -T4 -p$(grep '/open' {out}/ports/nmap_full.txt | awk '{{print $1}}' | cut -d'/' -f1 | tr '\\n' ',' | sed 's/,$//') {d} -oN {out}/ports/nmap_services.txt",
                    f"echo '[+] Service version scan done'"
                ]
            },
            {
                "tool": "Nmap (Vulnerability scripts)",
                "description": "Run Nmap NSE vulnerability scripts — CVE checks, default creds, known exploits",
                "commands": [
                    f"nmap -sV --script vuln -p$(grep '/open' {out}/ports/nmap_full.txt | awk '{{print $1}}' | cut -d'/' -f1 | tr '\\n' ',' | sed 's/,$//') {d} -oN {out}/ports/nmap_vulns.txt",
                    f"echo '[+] Nmap vuln scripts done'"
                ]
            },
            {
                "tool": "Masscan",
                "description": "Blazing-fast port scanner — scans entire internet at 10M packets/sec. Run as root.",
                "commands": [
                    f"masscan -p0-65535 {d} --rate=10000 -oL {out}/ports/masscan.txt",
                    f"echo '[+] Masscan done'"
                ]
            },
            {
                "tool": "RustScan",
                "description": "Ultra-fast Rust-based port scanner — finds open ports then hands off to Nmap",
                "commands": [
                    f"rustscan -a {d} --ulimit 5000 -- -sV -sC -oN {out}/ports/rustscan.txt",
                    f"echo '[+] RustScan done'"
                ]
            },
            {
                "tool": "Nmap (UDP scan)",
                "description": "UDP service discovery — finds DNS, SNMP, NTP, TFTP, and other UDP-based services",
                "commands": [
                    f"nmap -sU -T4 --top-ports 200 {d} -oN {out}/ports/nmap_udp.txt",
                    f"echo '[+] UDP scan done'"
                ]
            }
        ]
    })

    # ─── 6. TECHNOLOGY FINGERPRINTING ───────────────────────────────────────
    sections.append({
        "id": "techfp",
        "title": "Technology Fingerprinting",
        "icon": "🧩",
        "description": "Identify the technology stack, CMS, WAF, CDN, and server software running on the target.",
        "passive": True,
        "tools": [
            {
                "tool": "WhatWeb",
                "description": "Identifies CMS, blog platforms, JS libraries, server software, analytics, and more",
                "commands": [
                    f"whatweb -a 3 -v https://{d} | tee {out}/web/whatweb.txt",
                    f"whatweb -a 3 -v --color=never -i {out}/web/httpx_live.txt | tee {out}/web/whatweb_all.txt"
                ]
            },
            {
                "tool": "wafw00f",
                "description": "Detect and fingerprint Web Application Firewalls (WAF) on the target",
                "commands": [
                    f"wafw00f https://{d} -a | tee {out}/web/waf.txt",
                    f"cat {out}/web/httpx_live.txt | xargs -I{{}} wafw00f {{}} 2>/dev/null | tee {out}/web/waf_all.txt"
                ]
            },
            {
                "tool": "CMSeeK",
                "description": "CMS detection and deep fingerprinting for WordPress, Joomla, Drupal, and 170+ others",
                "commands": [
                    f"cmseek -u https://{d} --follow-redirect | tee {out}/web/cmseek.txt"
                ]
            },
            {
                "tool": "Nikto (header recon)",
                "description": "Lightweight web server scanner — checks headers, server software, dangerous files",
                "commands": [
                    f"nikto -h https://{d} -output {out}/web/nikto_{d_safe}.txt -Format txt",
                    f"echo '[+] Nikto done'"
                ]
            },
            {
                "tool": "SSL/TLS Analysis (testssl)",
                "description": "Comprehensive TLS/SSL testing — cipher suites, certificate chain, known vulnerabilities (BEAST, POODLE, Heartbleed)",
                "commands": [
                    f"testssl.sh --color 0 https://{d} | tee {out}/web/testssl.txt"
                ]
            }
        ]
    })

    # ─── 7. WEB ARCHIVES & HISTORICAL DATA ──────────────────────────────────
    sections.append({
        "id": "archives",
        "title": "Web Archives & Historical Data",
        "icon": "📚",
        "description": "Mine the Wayback Machine and Common Crawl for old URLs, endpoints, parameters, and forgotten assets.",
        "passive": True,
        "tools": [
            {
                "tool": "waybackurls",
                "description": "Fetch all URLs the Wayback Machine knows about for a domain — finds old endpoints, APIs, files",
                "commands": [
                    f"echo {d} | waybackurls | tee {out}/archives/waybackurls.txt",
                    f"echo '[+] Wayback URLs:' $(wc -l < {out}/archives/waybackurls.txt)"
                ]
            },
            {
                "tool": "gau (GetAllURLs)",
                "description": "Fetches known URLs from Wayback Machine, OTX, Common Crawl, and URLScan",
                "commands": [
                    f"echo {d} | gau --threads 5 --blacklist png,jpg,gif,css,woff,svg | tee {out}/archives/gau.txt",
                    f"echo '[+] GAU URLs:' $(wc -l < {out}/archives/gau.txt)"
                ]
            },
            {
                "tool": "waymore",
                "description": "Advanced wayback tool — finds more URLs with filtering, downloads response bodies",
                "commands": [
                    f"waymore -i {d} -mode U -oU {out}/archives/waymore_urls.txt",
                    f"echo '[+] Waymore done'"
                ]
            },
            {
                "tool": "unfurl",
                "description": "Parse and analyse URL structures — extracts domains, paths, params, keys from URL lists",
                "commands": [
                    f"cat {out}/archives/gau.txt | unfurl --unique keys | tee {out}/archives/param_keys.txt",
                    f"cat {out}/archives/gau.txt | unfurl --unique paths | tee {out}/archives/paths.txt",
                    f"cat {out}/archives/gau.txt | grep '=' | tee {out}/archives/urls_with_params.txt",
                    f"echo '[+] Param keys found:' $(wc -l < {out}/archives/param_keys.txt)"
                ]
            },
            {
                "tool": "Filter interesting files",
                "description": "Extract high-value file types from archive URLs — config files, backups, API endpoints",
                "commands": [
                    f"cat {out}/archives/gau.txt {out}/archives/waybackurls.txt | sort -u | grep -E '\\.php|\\.asp|\\.aspx|\\.jsp|\\.json|\\.xml|\\.env|\\.config|\\.bak|\\.old|\\.sql|\\.zip|\\.tar|\\.git' | tee {out}/archives/interesting_files.txt",
                    f"cat {out}/archives/gau.txt | grep -E 'api|admin|upload|backup|config|debug|token|key' | tee {out}/archives/interesting_endpoints.txt"
                ]
            },
            {
                "tool": "URLScan.io",
                "description": "Query URLScan.io API for previous scans, screenshots, and page info",
                "commands": [
                    f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{d}&size=100' | jq -r '.results[].page.url' | tee {out}/archives/urlscan.txt"
                ]
            }
        ]
    })

    # ─── 8. DIRECTORY & PATH BRUTEFORCING ───────────────────────────────────
    sections.append({
        "id": "dirscan",
        "title": "Directory & Path Bruteforcing",
        "icon": "📁",
        "description": "Discover hidden paths, admin panels, backup files, API endpoints, and misconfigurations.",
        "passive": False,
        "tools": [
            {
                "tool": "ffuf",
                "description": "Fast web fuzzer — extremely flexible, supports headers, POST data, VHost fuzzing",
                "commands": [
                    f"ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://{d}/FUZZ -mc 200,201,202,204,301,302,307,401,403,405 -c -t 50 -o {out}/dirs/ffuf_dirs.json",
                    f"ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u https://{d}/api/FUZZ -mc 200,201,202,204,301,302 -c -t 30 -o {out}/dirs/ffuf_api.json"
                ]
            },
            {
                "tool": "Gobuster",
                "description": "Go-based directory and DNS bruteforcer — fast and reliable",
                "commands": [
                    f"gobuster dir -u https://{d} -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x php,asp,aspx,jsp,html,txt,json,config,bak,old,zip -t 50 -o {out}/dirs/gobuster.txt",
                    f"gobuster vhost -u https://{d} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o {out}/dirs/gobuster_vhosts.txt"
                ]
            },
            {
                "tool": "dirsearch",
                "description": "Web path scanner with recursion support and smart detection of false positives",
                "commands": [
                    f"dirsearch -u https://{d} -e php,asp,aspx,jsp,html,json,xml,bak,zip,sql -t 30 -r --recursion-depth 2 -o {out}/dirs/dirsearch.txt"
                ]
            },
            {
                "tool": "feroxbuster",
                "description": "Recursive content discovery with auto-filtering and smart detection",
                "commands": [
                    f"feroxbuster -u https://{d} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt,json,js -t 50 -d 3 -o {out}/dirs/feroxbuster.txt"
                ]
            },
            {
                "tool": "Backup & Sensitive file hunting",
                "description": "Look for common backup files, config exposures, and sensitive paths",
                "commands": [
                    f"ffuf -w /usr/share/seclists/Discovery/Web-Content/CommonBackupExtensions.txt -u https://{d}/{d_safe}.FUZZ -mc 200 -o {out}/dirs/backup_files.json",
                    f"ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt -u https://{d}/FUZZ -mc 200 -o {out}/dirs/php_common.json"
                ]
            }
        ]
    })

    # ─── 9. JAVASCRIPT ANALYSIS ─────────────────────────────────────────────
    sections.append({
        "id": "jsanalysis",
        "title": "JavaScript File Analysis",
        "icon": "⚙️",
        "description": "Extract endpoints, secrets, API keys, and sensitive data from JavaScript files.",
        "passive": True,
        "tools": [
            {
                "tool": "getJS",
                "description": "Crawl the target and collect all JavaScript file URLs",
                "commands": [
                    f"getJS --url https://{d} --complete --output {out}/js/js_files.txt",
                    f"echo '[+] JS files found:' $(wc -l < {out}/js/js_files.txt)"
                ]
            },
            {
                "tool": "subjs",
                "description": "Fetch JS files from live hosts and archive them",
                "commands": [
                    f"cat {out}/web/httprobe_live.txt | subjs | tee {out}/js/subjs_files.txt"
                ]
            },
            {
                "tool": "LinkFinder",
                "description": "Extract endpoints and paths hidden inside JS files",
                "commands": [
                    f"python3 ~/tools/LinkFinder/linkfinder.py -i https://{d} -d -o {out}/js/linkfinder.html",
                    f"python3 ~/tools/LinkFinder/linkfinder.py -i {out}/js/js_files.txt -b -o {out}/js/endpoints.txt"
                ]
            },
            {
                "tool": "SecretFinder",
                "description": "Hunt for API keys, tokens, passwords, and secrets inside JS files",
                "commands": [
                    f"python3 ~/tools/SecretFinder/SecretFinder.py -i https://{d} -e -o {out}/js/secrets.html",
                    f"cat {out}/js/js_files.txt | while read url; do python3 ~/tools/SecretFinder/SecretFinder.py -i $url -o cli 2>/dev/null; done | tee {out}/js/all_secrets.txt"
                ]
            },
            {
                "tool": "grep (manual secret hunting)",
                "description": "Regex-based grep across downloaded JS for common secret patterns",
                "commands": [
                    f"grep -rE '(api_key|apikey|access_token|secret|password|passwd|token|bearer|auth|aws_|stripe_|private_key|client_secret)\\s*[:=]\\s*[\"\\'][^\"\\']+[\"\\']' {out}/js/ | tee {out}/js/grep_secrets.txt"
                ]
            }
        ]
    })

    # ─── 10. GOOGLE DORKS ───────────────────────────────────────────────────
    sections.append({
        "id": "dorks",
        "title": "Google Dorks & OSINT Search",
        "icon": "🎯",
        "description": "Targeted Google search operators to find exposed files, login portals, subdomains, and sensitive information indexed by search engines.",
        "passive": True,
        "tools": [
            {
                "tool": "Sensitive File Exposure",
                "description": "Find indexed sensitive files like configs, backups, logs, and environment files",
                "commands": [
                    f'# Open in browser: site:{d} ext:php OR ext:asp OR ext:aspx inurl:admin',
                    f'# site:{d} ext:env OR ext:config OR ext:conf OR ext:ini',
                    f'# site:{d} ext:sql OR ext:db OR ext:backup OR ext:bak OR ext:zip',
                    f'# site:{d} ext:log intext:error OR intext:warning OR intext:password'
                ]
            },
            {
                "tool": "Login & Admin Panels",
                "description": "Discover admin interfaces, login pages, and management portals",
                "commands": [
                    f'# site:{d} inurl:admin OR inurl:login OR inurl:wp-admin OR inurl:dashboard',
                    f'# site:{d} inurl:phpmyadmin OR inurl:cpanel OR inurl:webmail',
                    f'# site:{d} intitle:"admin panel" OR intitle:"login" OR intitle:"administrator"'
                ]
            },
            {
                "tool": "API & Endpoint Discovery",
                "description": "Find exposed API endpoints, swagger docs, and developer resources",
                "commands": [
                    f'# site:{d} inurl:api OR inurl:swagger OR inurl:graphql',
                    f'# site:{d} inurl:v1 OR inurl:v2 OR inurl:v3 filetype:json',
                    f'# site:{d} intext:"api_key" OR intext:"access_token" OR intext:"client_secret"'
                ]
            },
            {
                "tool": "Exposed Directories",
                "description": "Find open directory listings with potentially sensitive content",
                "commands": [
                    f'# site:{d} intitle:"index of" OR intitle:"directory listing"',
                    f'# site:{d} intitle:"index of" "parent directory"',
                    f'# site:{d} intext:"apache" OR intext:"nginx" intitle:"403 forbidden"'
                ]
            },
            {
                "tool": "GitHub / Pastebin OSINT",
                "description": "Find leaked code, credentials, or configs referencing the domain on code sharing sites",
                "commands": [
                    f'# site:github.com "{d}" password OR secret OR key OR token OR api',
                    f'# site:pastebin.com "{d}"',
                    f'# site:trello.com "{d}"',
                    f'# site:gitlab.com "{d}"'
                ]
            },
            {
                "tool": "theHarvester",
                "description": "OSINT tool to harvest emails, names, subdomains, IPs from public sources",
                "commands": [
                    f"theHarvester -d {d} -b all -l 500 -f {out}/osint/theharvester.html",
                    f"echo '[+] theHarvester done'"
                ]
            },
            {
                "tool": "EmailHarvest (h8mail)",
                "description": "Check harvested emails against breach databases",
                "commands": [
                    f"h8mail -t {d} -o {out}/osint/h8mail_results.csv",
                    f"echo '[+] Email breach check done'"
                ]
            }
        ]
    })

    # ─── 11. SCREENSHOTS ────────────────────────────────────────────────────
    sections.append({
        "id": "screenshots",
        "title": "Screenshot & Visual Recon",
        "icon": "📸",
        "description": "Automatically screenshot all live web assets to quickly identify interesting targets visually.",
        "passive": False,
        "tools": [
            {
                "tool": "gowitness",
                "description": "Fast headless Chromium-based screenshot tool — generates an HTML report of all targets",
                "commands": [
                    f"gowitness file -f {out}/web/httprobe_live.txt -P {out}/screenshots/ --delay 2",
                    f"gowitness report generate -n {out}/screenshots/report.html",
                    f"echo '[+] Screenshots saved to {out}/screenshots/'"
                ]
            },
            {
                "tool": "aquatone",
                "description": "Domain flyover tool — screenshots + header fingerprinting in one HTML report",
                "commands": [
                    f"cat {out}/web/httprobe_live.txt | aquatone -out {out}/screenshots/aquatone -screenshot-timeout 30000",
                    f"echo '[+] Aquatone report: {out}/screenshots/aquatone/aquatone_report.html'"
                ]
            },
            {
                "tool": "EyeWitness",
                "description": "Screenshot web, RDP, and VNC services — includes header/cert info per host",
                "commands": [
                    f"eyewitness --web --input-file {out}/web/httprobe_live.txt --output {out}/screenshots/eyewitness/ --timeout 30",
                    f"echo '[+] EyeWitness done'"
                ]
            }
        ]
    })

    # ─── 12. VULNERABILITY SCANNING ─────────────────────────────────────────
    sections.append({
        "id": "vulnscan",
        "title": "Vulnerability Scanning",
        "icon": "🔴",
        "description": "Automated vulnerability detection using template-based and pattern-based scanners.",
        "passive": False,
        "tools": [
            {
                "tool": "Nuclei (All templates)",
                "description": "Community-driven vulnerability scanner with 7000+ templates — CVEs, misconfigs, exposures, takeovers",
                "commands": [
                    f"nuclei -l {out}/web/httpx_live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o {out}/vulns/nuclei_all.txt -stats",
                    f"echo '[+] Nuclei scan done'"
                ]
            },
            {
                "tool": "Nuclei (Subdomain Takeover)",
                "description": "Detect dangling DNS records vulnerable to subdomain takeover",
                "commands": [
                    f"nuclei -l {out}/subdomains/resolved.txt -t ~/nuclei-templates/takeovers/ -o {out}/vulns/nuclei_takeovers.txt",
                    f"nuclei -l {out}/subdomains/resolved.txt -t ~/nuclei-templates/dns/ -o {out}/vulns/nuclei_dns.txt"
                ]
            },
            {
                "tool": "Nuclei (CVE templates)",
                "description": "Scan for known CVEs matching identified technologies",
                "commands": [
                    f"nuclei -l {out}/web/httpx_live.txt -t ~/nuclei-templates/cves/ -severity critical,high -o {out}/vulns/nuclei_cves.txt -stats"
                ]
            },
            {
                "tool": "Nikto",
                "description": "Classic web server scanner — 6700+ dangerous files, outdated software, server misconfigs",
                "commands": [
                    f"nikto -h https://{d} -C all -Format htm -output {out}/vulns/nikto.html",
                    f"echo '[+] Nikto done'"
                ]
            },
            {
                "tool": "subjack (Subdomain Takeover)",
                "description": "Check subdomains for potential takeover via fingerprinting CNAME records",
                "commands": [
                    f"subjack -w {out}/subdomains/resolved.txt -t 100 -timeout 30 -o {out}/vulns/subjack.txt -ssl",
                    f"echo '[+] subjack done'"
                ]
            },
            {
                "tool": "CORS Misconfig Scanner",
                "description": "Test for CORS misconfigurations that allow cross-origin data theft",
                "commands": [
                    f"python3 ~/tools/CORScanner/cors_scan.py -i {out}/web/httpx_live.txt -t 50 | tee {out}/vulns/cors.txt"
                ]
            }
        ]
    })

    # ─── 13. CLOUD & ASSET DISCOVERY ────────────────────────────────────────
    sections.append({
        "id": "cloud",
        "title": "Cloud & Asset Discovery",
        "icon": "☁️",
        "description": "Discover cloud storage buckets, cloud assets, and infrastructure tied to the target domain.",
        "passive": True,
        "tools": [
            {
                "tool": "S3Scanner",
                "description": "Find open or misconfigured S3 buckets associated with the target",
                "commands": [
                    f"s3scanner -bucket {d} | tee {out}/web/s3_buckets.txt",
                    f"python3 ~/tools/S3Scanner/s3scanner.py --include-closed --out-file {out}/web/s3_all.txt --threads 20 {d}"
                ]
            },
            {
                "tool": "cloud_enum",
                "description": "Multi-cloud asset discovery — AWS, Azure, GCP buckets, blob storage, app services",
                "commands": [
                    f"python3 ~/tools/cloud_enum/cloud_enum.py -k {d} -k {d.replace('.', '')} --disable-azure --disable-gcp -l {out}/web/cloud_aws.txt",
                    f"python3 ~/tools/cloud_enum/cloud_enum.py -k {d} -l {out}/web/cloud_all.txt"
                ]
            },
            {
                "tool": "Shodan (CLI)",
                "description": "Query Shodan for internet-exposed assets, open ports, and banners (requires API key)",
                "commands": [
                    f"shodan domain {d} | tee {out}/web/shodan_domain.txt",
                    f"shodan search 'hostname:{d}' --fields ip_str,port,org,product | tee {out}/web/shodan_search.txt"
                ]
            },
            {
                "tool": "Censys (CLI)",
                "description": "Query Censys for hosts with matching certificates and domain references",
                "commands": [
                    f"censys search 'parsed.names: {d}' --index-type certificates --fields parsed.names,metadata.updated_at | tee {out}/web/censys.txt"
                ]
            }
        ]
    })

    # ─── 14. FINAL CONSOLIDATION ────────────────────────────────────────────
    sections.append({
        "id": "consolidate",
        "title": "Consolidate & Report",
        "icon": "📋",
        "description": "Merge all findings into a structured summary report for easy review.",
        "passive": True,
        "tools": [
            {
                "tool": "Generate Summary",
                "description": "Produce a quick stats summary of all recon output",
                "commands": [
                    f"echo '===== AKID RECON SUMMARY FOR {d.upper()} =====' > {out}/SUMMARY.txt",
                    f"echo 'Subdomains (unique):' $(wc -l < {out}/subdomains/all_subdomains.txt 2>/dev/null || echo 0) >> {out}/SUMMARY.txt",
                    f"echo 'Resolved subdomains:' $(wc -l < {out}/subdomains/resolved.txt 2>/dev/null || echo 0) >> {out}/SUMMARY.txt",
                    f"echo 'Live web hosts:' $(wc -l < {out}/web/httpx_live.txt 2>/dev/null || echo 0) >> {out}/SUMMARY.txt",
                    f"echo 'Wayback URLs:' $(wc -l < {out}/archives/gau.txt 2>/dev/null || echo 0) >> {out}/SUMMARY.txt",
                    f"echo 'Nuclei findings:' $(wc -l < {out}/vulns/nuclei_all.txt 2>/dev/null || echo 0) >> {out}/SUMMARY.txt",
                    f"echo 'JS files:' $(wc -l < {out}/js/js_files.txt 2>/dev/null || echo 0) >> {out}/SUMMARY.txt",
                    f"cat {out}/SUMMARY.txt"
                ]
            },
            {
                "tool": "Archive output",
                "description": "Compress the entire recon directory for storage and sharing",
                "commands": [
                    f"tar -czvf ~/recon/{d_safe}_recon_$(date +%Y%m%d).tar.gz ~/recon/{d}/",
                    f"echo '[+] Recon archive created: ~/recon/{d_safe}_recon_$(date +%Y%m%d).tar.gz'"
                ]
            }
        ]
    })

    return sections
