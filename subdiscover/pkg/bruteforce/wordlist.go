package bruteforce

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Wordlist struct {
	words []string
}

// Embedded minimal wordlist as fallback if file not found
var fallbackWords = []string{
	"www", "mail", "api", "dev", "test", "admin", "app", "blog", "shop",
	"secure", "vpn", "cloud", "backup", "db", "cdn", "static", "img",
	"media", "docs", "wiki", "support", "status", "monitor", "dashboard",
	"gateway", "auth", "login", "account", "user", "config", "web",
	"staging", "prod", "production", "beta", "alpha", "demo", "portal",
	"ftp", "smtp", "pop", "imap", "mx", "ns1", "ns2", "ns3", "dns",
	"remote", "vpn2", "proxy", "load", "lb", "internal", "intranet",
	"extranet", "m", "mobile", "wap", "old", "new", "v1", "v2", "v3",
	"api1", "api2", "api3", "rest", "graphql", "ws", "websocket",
	"chat", "meet", "video", "stream", "download", "upload", "files",
	"assets", "images", "js", "css", "fonts", "data", "redis", "mongo",
	"mysql", "postgres", "elastic", "kibana", "grafana", "prometheus",
	"jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
	"sonar", "nexus", "artifactory", "registry", "docker", "k8s",
	"kubernetes", "helm", "rancher", "vault", "consul", "nomad",
	"dev1", "dev2", "staging1", "staging2", "prod1", "prod2",
	"east", "west", "us", "eu", "ap", "us-east", "us-west", "eu-west",
	"corporate", "corp", "office", "hr", "finance", "legal", "marketing",
	"sales", "engineering", "it", "helpdesk", "noc", "soc",
	"payment", "payments", "billing", "invoice", "order", "orders",
	"cart", "checkout", "store", "ecommerce", "merchant",
	"sso", "oauth", "openid", "saml", "ldap", "ad",
	"nagios", "zabbix", "icinga", "pagerduty", "opsgenie",
	"search", "elastic", "solr", "algolia",
	"queue", "rabbitmq", "kafka", "nats",
	"metrics", "logs", "tracing", "jaeger", "zipkin",
	"mail2", "smtp2", "exchange", "webmail", "owa",
	"sandbox", "test1", "test2", "qa", "uat",
	"reporting", "report", "analytics", "bi", "warehouse",
	"archive", "archives", "old-api", "legacy",
}

func LoadWordlist(path string) (*Wordlist, error) {
	file, err := os.Open(path)
	if err != nil {
		// Use fallback
		fmt.Printf("  [!] Wordlist not found at %s, using built-in list (%d words)\n", path, len(fallbackWords))
		return &Wordlist{words: fallbackWords}, nil
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := words[:0]
	for _, w := range words {
		if !seen[w] {
			seen[w] = true
			unique = append(unique, w)
		}
	}

	return &Wordlist{words: unique}, nil
}

func (w *Wordlist) GenerateSubdomains(domain string) []string {
	result := make([]string, len(w.words))
	for i, word := range w.words {
		result[i] = word + "." + domain
	}
	return result
}

func (w *Wordlist) Size() int {
	return len(w.words)
}
