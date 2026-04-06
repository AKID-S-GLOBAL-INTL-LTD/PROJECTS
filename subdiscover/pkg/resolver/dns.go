package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ─── Result types ─────────────────────────────────────────────────────────────

type Result struct {
	Subdomain string
	IPs       []string
	IPv6s     []string
	CNAMEs    []string
	IsCDN     bool
	Error     error
}

type AssetResult struct {
	Domain string
	MX     []MXRecord
	NS     []string
	TXT    []string
	SOA    *SOARecord
}

type MXRecord struct {
	Host     string
	Priority uint16
}

type SOARecord struct {
	Ns      string
	Mbox    string
	Serial  uint32
	Refresh uint32
}

// ─── CDN fingerprints ─────────────────────────────────────────────────────────

var cdnPatterns = []string{
	"cloudfront.net", "akamaiedge.net", "akamaitechnologies.com",
	"fastly.net", "cloudflare.com", "cdn.cloudflare.net",
	"azureedge.net", "amazonaws.com", "googleusercontent.com",
	"edgekey.net", "edgesuite.net", "llnwd.net", "cachefly.net",
	"incapdns.net", "sucuri.net", "stackpathcdn.com", "bunnycdn.com",
	"netlify.app", "vercel.app", "pages.dev", "wixdns.net",
	"squarespace.com", "shopify.com", "github.io",
}

// ─── Resolver ─────────────────────────────────────────────────────────────────

type Resolver struct {
	client  *dns.Client
	servers []string
	retries int
	cache   sync.Map
}

var DefaultResolvers = []string{
	"1.1.1.1:53",        // Cloudflare
	"8.8.8.8:53",        // Google
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
	"8.8.4.4:53",        // Google secondary
}

func NewResolver(timeout time.Duration, retries int) *Resolver {
	return &Resolver{
		client:  &dns.Client{Timeout: timeout},
		servers: DefaultResolvers,
		retries: retries,
	}
}

// Resolve resolves a subdomain: A records + CNAME chain + CDN detection
func (r *Resolver) Resolve(ctx context.Context, subdomain string) *Result {
    if cached, ok := r.cache.Load(subdomain); ok {
        return cached.(*Result)
    }

    result := &Result{Subdomain: subdomain}

    // Resolve A + AAAA records
    for attempt := 0; attempt < r.retries; attempt++ {
        for _, server := range r.servers {
            select {
            case <-ctx.Done():
                result.Error = ctx.Err()
                return result
            default:
            }

            ipv4s, ipv6s, err := r.queryIPs(subdomain, server)
            if err == nil && (len(ipv4s) > 0 || len(ipv6s) > 0) {
                result.IPs = ipv4s
                result.IPv6s = ipv6s
                goto resolved
            }
        }
        time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
    }

resolved:
    if len(result.IPs) == 0 && len(result.IPv6s) == 0 {
        result.Error = fmt.Errorf("no resolution")
        return result
    }

    // CNAME chain
    result.CNAMEs, _ = r.queryCNAME(subdomain, r.servers[0])

    // CDN detection
    for _, c := range result.CNAMEs {
        lower := strings.ToLower(c)
        for _, pat := range cdnPatterns {
            if strings.Contains(lower, pat) {
                result.IsCDN = true
                break
            }
        }
    }

    r.cache.Store(subdomain, result)
    return result
}

// GetAssets fetches MX, NS, TXT, SOA records for the root domain
func (r *Resolver) GetAssets(domain string) *AssetResult {
	ar := &AssetResult{Domain: domain}
	server := r.servers[0]

	// MX
	m := newMsg(domain, dns.TypeMX)
	if resp, _, err := r.client.Exchange(m, server); err == nil {
		for _, ans := range resp.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				ar.MX = append(ar.MX, MXRecord{
					Host:     strings.TrimSuffix(mx.Mx, "."),
					Priority: mx.Preference,
				})
			}
		}
	}

	// NS
	m = newMsg(domain, dns.TypeNS)
	if resp, _, err := r.client.Exchange(m, server); err == nil {
		for _, ans := range resp.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				ar.NS = append(ar.NS, strings.TrimSuffix(ns.Ns, "."))
			}
		}
	}

	// TXT
	m = newMsg(domain, dns.TypeTXT)
	if resp, _, err := r.client.Exchange(m, server); err == nil {
		for _, ans := range resp.Answer {
			if t, ok := ans.(*dns.TXT); ok {
				ar.TXT = append(ar.TXT, strings.Join(t.Txt, " "))
			}
		}
	}

	// SOA
	m = newMsg(domain, dns.TypeSOA)
	if resp, _, err := r.client.Exchange(m, server); err == nil {
		for _, ans := range resp.Answer {
			if s, ok := ans.(*dns.SOA); ok {
				ar.SOA = &SOARecord{
					Ns:      strings.TrimSuffix(s.Ns, "."),
					Mbox:    strings.TrimSuffix(s.Mbox, "."),
					Serial:  s.Serial,
					Refresh: s.Refresh,
				}
			}
		}
	}

	return ar
}

// IsWildcard detects wildcard DNS for a domain
func (r *Resolver) IsWildcard(domain string) bool {
	probe := fmt.Sprintf("subdiscover-probe-%d.%s", time.Now().UnixNano(), domain)
	ipv4s, ipv6s, err := r.queryIPs(probe, r.servers[0])
	return err == nil && (len(ipv4s) > 0 || len(ipv6s) > 0)
}

// ReverseLookup performs a PTR lookup
func (r *Resolver) ReverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func newMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

func (r *Resolver) queryIPs(name, server string) ([]string, []string, error) {
    resp, _, err := r.client.Exchange(newMsg(name, dns.TypeA), server)
    if err != nil {
        return nil, nil, err
    }

    var ipv4s []string
    for _, ans := range resp.Answer {
        if a, ok := ans.(*dns.A); ok {
            ipv4s = append(ipv4s, a.A.String())
        }
    }

    resp6, _, err := r.client.Exchange(newMsg(name, dns.TypeAAAA), server)
    if err != nil {
        return ipv4s, nil, nil // don't fail completely if AAAA fails
    }

    var ipv6s []string
    for _, ans := range resp6.Answer {
        if aaaa, ok := ans.(*dns.AAAA); ok {
            ipv6s = append(ipv6s, aaaa.AAAA.String())
        }
    }

    return ipv4s, ipv6s, nil
}

func (r *Resolver) queryCNAME(name, server string) ([]string, error) {
	resp, _, err := r.client.Exchange(newMsg(name, dns.TypeCNAME), server)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ans := range resp.Answer {
		if cn, ok := ans.(*dns.CNAME); ok {
			out = append(out, strings.TrimSuffix(cn.Target, "."))
		}
	}
	return out, nil
}
