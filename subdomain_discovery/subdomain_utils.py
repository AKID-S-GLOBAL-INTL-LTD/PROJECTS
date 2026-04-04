import dns.resolver
import dns.exception
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

resolver = dns.resolver.Resolver()
resolver.timeout = 2
resolver.lifetime = 3

def resolve_subdomain(subdomain, domain):
    full_domain = f"{subdomain}.{domain}"
    ips = []
    cname = None
    try:
        answers = resolver.resolve(full_domain, 'A')
        ips = [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        try:
            answers = resolver.resolve(full_domain, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            try:
                a_answers = resolver.resolve(cname, 'A')
                ips = [str(r) for r in a_answers]
            except:
                pass
        except:
            return None
    except:
        return None
    return {
        'subdomain': subdomain,
        'full_domain': full_domain,
        'ips': ips if ips else [],
        'cname': cname
    }

def check_http(subdomain_info, timeout=2):
    full = subdomain_info['full_domain']
    results = []
    for scheme in ['http', 'https']:
        url = f"{scheme}://{full}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            title = ''
            if 'text/html' in resp.headers.get('content-type', ''):
                import re
                match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()[:100]
            results.append({'url': url, 'status': resp.status_code, 'title': title})
        except:
            continue
    return results

def discover(domain, wordlist_path, http_check=True, max_subdomains=10000, max_workers=30):
    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()][:max_subdomains]
    except FileNotFoundError:
        yield {'type': 'error', 'message': f'Wordlist not found: {wordlist_path}'}
        return

    total = len(subdomains)
    yield {'type': 'progress', 'total': total, 'current': 0}
    
    resolved_count = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_sub = {executor.submit(resolve_subdomain, sub, domain): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            resolved_count += 1
            # Send progress every 100 completions (reduces UI updates)
            if resolved_count % 100 == 0 or resolved_count == total:
                yield {'type': 'progress', 'total': total, 'current': resolved_count}
            try:
                result = future.result(timeout=3)
            except:
                continue
            if result:
                if http_check:
                    try:
                        result['http'] = check_http(result)
                    except:
                        result['http'] = []
                yield {'type': 'result', 'data': result}
    yield {'type': 'done'}