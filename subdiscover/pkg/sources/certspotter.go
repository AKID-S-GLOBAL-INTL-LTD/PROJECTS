package sources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type certspotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

func GetFromCertspotter(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var entries []certspotterEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		for _, name := range e.DNSNames {
			name = strings.ToLower(strings.TrimPrefix(name, "*."))
			if strings.HasSuffix(name, "."+domain) || name == domain {
				seen[name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}
