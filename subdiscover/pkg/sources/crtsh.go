package sources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func GetFromCRTSH(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
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
