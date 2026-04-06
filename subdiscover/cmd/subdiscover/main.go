package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/abrahamakinwale/PROJECTS/subdiscover/pkg/bruteforce"
	"github.com/abrahamakinwale/PROJECTS/subdiscover/pkg/display"
	"github.com/abrahamakinwale/PROJECTS/subdiscover/pkg/httpprobe"
	"github.com/abrahamakinwale/PROJECTS/subdiscover/pkg/output"
	"github.com/abrahamakinwale/PROJECTS/subdiscover/pkg/resolver"
	"github.com/abrahamakinwale/PROJECTS/subdiscover/pkg/sources"
)

func main() {
	display.PrintBanner()

	if len(os.Args) < 2 {
		fmt.Println("Usage: subdiscover -d example.com")
		os.Exit(1)
	}

	domain := ""
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "-d" && i+1 < len(os.Args) {
			domain = os.Args[i+1]
		}
	}

	if domain == "" {
		display.Error("Please provide a domain using -d")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Handle CTRL+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		display.Warn("Stopping scan...")
		cancel()
	}()

	startTime := time.Now()

	// =========================
	// PHASE 1: SUBDOMAIN ENUM
	// =========================
	display.PrintSectionHeader("SUBDOMAIN COLLECTION")

	allSubs := make(map[string]bool)

	// Load wordlist
	wl, err := bruteforce.LoadWordlist("wordlists/subdomains.txt")
	if err != nil {
		display.Error("Failed to load wordlist: %v", err)
		os.Exit(1)
	}

	for _, s := range wl.GenerateSubdomains(domain) {
		allSubs[s] = true
	}

	// Passive (crt.sh)
	ctSubs, _ := sources.GetFromCRTSH(domain)
	for _, s := range ctSubs {
		allSubs[s] = true
	}

	// Convert to slice
	subList := make([]string, 0, len(allSubs))
	for s := range allSubs {
		subList = append(subList, s)
	}

	sort.Strings(subList)

	display.PrintInfo(fmt.Sprintf("Total subdomains: %d", len(subList)))
	display.PrintSectionFooter()

	// =========================
	// PHASE 2: DNS RESOLUTION
	// =========================
	display.PrintSectionHeader("DNS RESOLUTION")

	dnsResolver := resolver.NewResolver(3*time.Second, 3)
	pool := bruteforce.NewPool(dnsResolver, 50)

	results := pool.ResolveAll(ctx, subList, true)

	display.PrintInfo(fmt.Sprintf("Resolved: %d", len(results)))
	display.PrintSectionFooter()

	// =========================
	// PHASE 3: HTTP PROBE
	// =========================
	display.PrintSectionHeader("HTTP PROBE")

	var httpResults []*httpprobe.Result
	var wg sync.WaitGroup

	for _, r := range results {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			res := httpprobe.Probe(sub)
			httpResults = append(httpResults, res)
		}(r.Subdomain)
	}

	wg.Wait()

	live := 0
	for _, r := range httpResults {
		if r.IsAlive {
			live++
			display.PrintHTTPResult(r.Subdomain, r.URL, r.Title, r.StatusCode, r.ContentLen, r.Technologies)
		}
	}

	display.PrintInfo(fmt.Sprintf("Live hosts: %d", live))
	display.PrintSectionFooter()

	// =========================
	// OUTPUT
	// =========================
	report := output.BuildReport(domain, startTime, results, httpResults, nil)
	output.SaveJSON("results.json", report)

	display.Success("Saved to results.json")
	display.PrintFooter()
}
