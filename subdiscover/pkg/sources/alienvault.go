package sources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type avResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func GetFromAlienVault(domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "SubDiscover/2.0 (AKID Global Cyber Security)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result avResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, e := range result.PassiveDNS {
		name := strings.ToLower(e.Hostname)
		if strings.HasSuffix(name, "."+domain) || name == domain {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}
