package sources

import (
	"context"
	"fmt"
	"sync"

	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/display"
)

// GatherAll queries all OSINT sources concurrently and returns subdomain→source map
func GatherAll(ctx context.Context, domain string) map[string]string {
	type srcDef struct {
		name string
		fn   func(string) ([]string, error)
	}

	srcs := []srcDef{
		{"crt.sh", GetFromCRTSH},
		{"certspotter", GetFromCertspotter},
		{"hackertarget", GetFromHackertarget},
		{"alienvault", GetFromAlienVault},
	}

	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, src := range srcs {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		go func(s srcDef) {
			defer wg.Done()
			sp := display.NewSpinner("Querying " + s.name)
			sp.Start()
			subs, err := s.fn(domain)
			if err != nil {
				sp.Stop("")
				display.PrintWarn(fmt.Sprintf("%s: %v", s.name, err))
				return
			}
			mu.Lock()
			count := 0
			for _, sub := range subs {
				if _, exists := results[sub]; !exists {
					results[sub] = s.name
					count++
				}
			}
			mu.Unlock()
			sp.Stop(fmt.Sprintf("%d new subdomains", count))
		}(src)
	}
	wg.Wait()
	return results
}
