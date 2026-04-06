package sources

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func GetFromHackertarget(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 {
			name := strings.ToLower(strings.TrimSpace(parts[0]))
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
