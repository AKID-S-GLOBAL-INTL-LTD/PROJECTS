package httpprobe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Result holds the result of probing a subdomain over HTTP/HTTPS
type Result struct {
	Subdomain   string
	URL         string
	StatusCode  int
	Title       string
	Server      string
	ContentLen  int64
	Technologies []string
	IsAlive     bool
	IsHTTPS     bool
	Redirect    string
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

// Probe checks both HTTPS and HTTP for a subdomain
func Probe(subdomain string) *Result {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)
		result := tryProbe(client, subdomain, url, scheme == "https")
		if result.IsAlive {
			return result
		}
	}

	return &Result{Subdomain: subdomain, IsAlive: false}
}

func tryProbe(client *http.Client, subdomain, url string, isHTTPS bool) *Result {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &Result{Subdomain: subdomain}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 SubDiscover/2.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return &Result{Subdomain: subdomain}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	bodyStr := string(body)

	result := &Result{
		Subdomain:  subdomain,
		URL:        url,
		StatusCode: resp.StatusCode,
		ContentLen: resp.ContentLength,
		Server:     resp.Header.Get("Server"),
		IsAlive:    true,
		IsHTTPS:    isHTTPS,
	}

	// Extract redirect location
	if loc := resp.Header.Get("Location"); loc != "" {
		result.Redirect = loc
	}

	// Extract title
	if matches := titleRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		result.Title = strings.TrimSpace(matches[1])
	}

	// Technology fingerprinting
	result.Technologies = detectTech(resp, bodyStr)

	return result
}

// detectTech performs basic technology fingerprinting
func detectTech(resp *http.Response, body string) []string {
	var techs []string

	server := strings.ToLower(resp.Header.Get("Server"))
	powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
	xGen := strings.ToLower(resp.Header.Get("X-Generator"))
	bodyLow := strings.ToLower(body)

	// Server headers
	for _, t := range []struct{ pat, name string }{
		{"nginx", "Nginx"}, {"apache", "Apache"}, {"iis", "IIS"},
		{"caddy", "Caddy"}, {"openresty", "OpenResty"}, {"litespeed", "LiteSpeed"},
	} {
		if strings.Contains(server, t.pat) {
			techs = append(techs, t.name)
		}
	}

	// X-Powered-By
	for _, t := range []struct{ pat, name string }{
		{"php", "PHP"}, {"asp.net", "ASP.NET"}, {"express", "Express.js"},
		{"node", "Node.js"}, {"ruby", "Ruby"}, {"python", "Python"},
	} {
		if strings.Contains(powered, t.pat) {
			techs = append(techs, t.name)
		}
	}

	// Body fingerprints
	for _, t := range []struct{ pat, name string }{
		{"wp-content", "WordPress"}, {"drupal.org", "Drupal"},
		{"joomla", "Joomla"}, {"shopify", "Shopify"},
		{"react", "React"}, {"vue.js", "Vue.js"}, {"angular", "Angular"},
		{"jquery", "jQuery"}, {"bootstrap", "Bootstrap"},
		{"__next", "Next.js"}, {"nuxt", "Nuxt.js"},
		{"laravel", "Laravel"}, {"django", "Django"},
		{"grafana", "Grafana"}, {"kibana", "Kibana"},
	} {
		if strings.Contains(bodyLow, t.pat) {
			techs = append(techs, t.name)
		}
	}

	// Security headers
	if resp.Header.Get("Strict-Transport-Security") != "" {
		techs = append(techs, "HSTS")
	}
	if xGen != "" {
		techs = append(techs, xGen)
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := techs[:0]
	for _, t := range techs {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}
	return unique
}
