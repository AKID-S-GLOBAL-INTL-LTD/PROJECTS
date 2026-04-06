package bruteforce

import (
	"context"
	"sync"

	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/display"
	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/resolver"
)

type Pool struct {
	resolver *resolver.Resolver
	workers  int
}

func NewPool(r *resolver.Resolver, workers int) *Pool {
	return &Pool{resolver: r, workers: workers}
}

func (p *Pool) ResolveAll(ctx context.Context, subdomains []string, showProgress bool) []*resolver.Result {
	jobs := make(chan string, len(subdomains))
	results := make(chan *resolver.Result, 512)

	var progress *display.LiveProgress
	if showProgress {
		progress = display.NewProgress(len(subdomains), "DNS Resolving")
		progress.Start()
	}

	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res := p.resolver.Resolve(ctx, sub)
					if showProgress {
						progress.Inc()
					}
					if res.Error == nil && len(res.IPs) > 0 {
						if showProgress {
							progress.IncFound()
						}
						results <- res
					}
				}
			}
		}()
	}

	for _, s := range subdomains {
		jobs <- s
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []*resolver.Result
	for r := range results {
		allResults = append(allResults, r)
	}

	if showProgress {
		progress.Stop()
	}

	return allResults
}
