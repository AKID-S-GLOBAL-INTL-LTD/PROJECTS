package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/bruteforce"
	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/display"
	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/httpprobe"
	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/output"
	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/resolver"
	"github.com/AKID-S-GLOBAL-INTL-LTD/subdiscover/pkg/sources"
)

// Config holds all scan configuration
type Config struct {
	Domain       string
	Threads      int
	OutputFile   string
	OutputFmt    string
	EnableHTTP   bool
	EnableCT     bool
	EnableOSINT  bool
	EnableAssets bool
	Wordlist     string
	Timeout      int
	Verbose      bool
}

func main() {
	display.PrintBanner()

	cfg := parseConfig()

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		display.Warn("Interrupt received — stopping gracefully...")
		cancel()
	}()

	startTime := time.Now()
	runScan(ctx, cfg, startTime)
	display.PrintFooter()
}

// runScan is the main scanning pipeline
func runScan(ctx context.Context, cfg *Config, startTime time.Time) {

	// ══════════════════════════════════════════════════════
	// PHASE 1 — Subdomain Collection
	// ══════════════════════════════════════════════════════
	display.PrintSectionHeader("PHASE 1 · SUBDOMAIN COLLECTION")

	allSubs := make(map[string]string) // subdomain → source

	// Wordlist bruteforce
	var wl *bruteforce.Wordlist
	var err error
	if cfg.Wordlist != "" {
		wl, err = bruteforce.LoadWordlist(cfg.Wordlist)
		if err != nil {
			display.Warn("Wordlist error (%v) — using built-in", err)
			wl = bruteforce.LoadBuiltin()
		}
	} else {
		wl = bruteforce.LoadBuiltin()
	}
	display.Success("Wordlist loaded: %d entries", wl.Size())
	for _, s := range wl.GenerateSubdomains(cfg.Domain) {
		allSubs[s] = "wordlist"
	}

	// CT Logs
	if cfg.EnableCT {
		sp := display.NewSpinner("Querying crt.sh CT logs")
		sp.Start()
		ctSubs, err := sources.GetFromCRTSH(cfg.Domain)
		if err != nil {
			sp.Stop("")
			display.Warn("CT logs: %v", err)
		} else {
			added := 0
			for _, s := range ctSubs {
				if _, exists := allSubs[s]; !exists {
					allSubs[s] = "crt.sh"
					added++
				}
			}
			sp.Stop(fmt.Sprintf("%d new subdomains", added))
		}
	}

	// OSINT sources
	if cfg.EnableOSINT {
		display.PrintInfo("Running OSINT sources concurrently...")
		osintMap := sources.GatherAll(ctx, cfg.Domain)
		for sub, src := range osintMap {
			if _, exists := allSubs[sub]; !exists {
				allSubs[sub] = src
			}
		}
		display.Success("OSINT complete — total unique: %d", len(allSubs))
	}

	// Flatten to sorted slice
	subList := make([]string, 0, len(allSubs))
	for s := range allSubs {
		subList = append(subList, s)
	}
	sort.Strings(subList)

	display.PrintInfo("Total unique targets to resolve: %d", len(subList))
	display.PrintSectionFooter()

	// ══════════════════════════════════════════════════════
	// PHASE 2 — DNS Resolution
	// ══════════════════════════════════════════════════════
	display.PrintSectionHeader("PHASE 2 · DNS RESOLUTION")
	display.PrintInfo("Resolving with %d threads...", cfg.Threads)
	fmt.Println()

	dnsResolver := resolver.NewResolver(time.Duration(cfg.Timeout)*time.Second, 3)
	pool := bruteforce.NewPool(dnsResolver, cfg.Threads)

	// Use LiveProgress for DNS phase
	prog := display.NewProgress(len(subList), "DNS")
	prog.Start()

	results := pool.ResolveAll(ctx, subList, func(done, total int) {
		prog.Inc()
	})

	// Count found after resolve
	prog.IncFound() // not used per-item here, just stop cleanly
	prog.Stop()

	fmt.Println()
	display.Success("Active subdomains resolved: %d / %d", len(results), len(subList))
	fmt.Println()

	// Print results table
	display.PrintSectionHeader("DISCOVERED SUBDOMAINS")
	display.PrintTableHeader()
	for _, r := range results {
		display.PrintSubdomain(0, r.Subdomain, r.IPs, r.IsCDN, r.CNAMEs)
	}
	display.PrintSectionFooter()

	// ══════════════════════════════════════════════════════
	// PHASE 3 — DNS Asset Enumeration
	// ══════════════════════════════════════════════════════
	var assetResult *resolver.AssetResult
	if cfg.EnableAssets {
		display.PrintSectionHeader("PHASE 3 · DNS ASSET ENUMERATION")
		sp := display.NewSpinner("Fetching MX, NS, TXT, SOA records")
		sp.Start()
		assetResult = dnsResolver.GetAssets(cfg.Domain)
		sp.Stop(fmt.Sprintf("NS=%d  MX=%d  TXT=%d",
			len(assetResult.NS), len(assetResult.MX), len(assetResult.TXT)))
		fmt.Println()

		for _, ns := range assetResult.NS {
			display.PrintAsset("NS", ns, "nameserver")
		}
		for _, mx := range assetResult.MX {
			display.PrintAsset("MX", mx.Host, fmt.Sprintf("priority=%d", mx.Priority))
		}
		for _, txt := range assetResult.TXT {
			label := ""
			low := strings.ToLower(txt)
			switch {
			case strings.HasPrefix(low, "v=spf"):
				label = "SPF record"
			case strings.Contains(low, "dmarc"):
				label = "DMARC policy"
			case strings.Contains(low, "google-site-verification"):
				label = "Google verification"
			case strings.Contains(low, "docusign"):
				label = "DocuSign verification"
			}
			if len(txt) > 72 {
				txt = txt[:69] + "..."
			}
			display.PrintAsset("TXT", txt, label)
		}
		if assetResult.SOA != nil {
			display.PrintAsset("SOA", assetResult.SOA.Ns,
				fmt.Sprintf("serial=%d  mbox=%s", assetResult.SOA.Serial, assetResult.SOA.Mbox))
		}
		display.PrintSectionFooter()
	}

	// ══════════════════════════════════════════════════════
	// PHASE 4 — HTTP / HTTPS Probing
	// ══════════════════════════════════════════════════════
	var httpResults []*httpprobe.Result

	if cfg.EnableHTTP && len(results) > 0 {
		display.PrintSectionHeader("PHASE 4 · HTTP / HTTPS PROBING")
		display.PrintInfo("Probing %d subdomains (HTTPS-first)...", len(results))
		fmt.Println()

		httpProg := display.NewProgress(len(results), "HTTP probe")
		httpProg.Start()

		httpCh := make(chan *httpprobe.Result, len(results))
		var httpWg sync.WaitGroup
		sem := make(chan struct{}, cfg.Threads/2+5)

		for _, r := range results {
			httpWg.Add(1)
			go func(sub string) {
				defer httpWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				select {
				case <-ctx.Done():
					return
				default:
				}
				pr := httpprobe.Probe(sub)
				if pr.IsAlive {
					httpProg.IncFound()
				}
				httpProg.Inc()
				httpCh <- pr
			}(r.Subdomain)
		}

		go func() {
			httpWg.Wait()
			close(httpCh)
		}()

		for pr := range httpCh {
			httpResults = append(httpResults, pr)
		}
		httpProg.Stop()
		fmt.Println()

		// Print live results
		liveCount := 0
		for _, pr := range httpResults {
			if pr.IsAlive {
				liveCount++
				display.PrintHTTPResult(pr.Subdomain, pr.URL, pr.Title, pr.StatusCode, pr.ContentLen, pr.Technologies)
			}
		}
		fmt.Println()
		display.Success("Live web services: %d", liveCount)
		display.PrintSectionFooter()
	}

	// ══════════════════════════════════════════════════════
	// PHASE 5 — Output
	// ══════════════════════════════════════════════════════
	report := output.BuildReport(cfg.Domain, startTime, results, httpResults, assetResult)

	if cfg.OutputFile != "" {
		display.PrintSectionHeader("PHASE 5 · SAVING RESULTS")
		outPath := cfg.OutputFile
		ext := strings.ToLower(cfg.OutputFmt)

		var saveErr error
		switch ext {
		case "txt":
			if !strings.HasSuffix(outPath, ".txt") {
				outPath = strings.TrimSuffix(outPath, filepath.Ext(outPath)) + ".txt"
			}
			saveErr = output.SaveTXT(outPath, report)
		case "md", "markdown":
			if !strings.HasSuffix(outPath, ".md") {
				outPath = strings.TrimSuffix(outPath, filepath.Ext(outPath)) + ".md"
			}
			saveErr = output.SaveMarkdown(outPath, report)
		default:
			if !strings.HasSuffix(outPath, ".json") {
				outPath = strings.TrimSuffix(outPath, filepath.Ext(outPath)) + ".json"
			}
			saveErr = output.SaveJSON(outPath, report)
		}

		if saveErr != nil {
			display.Error("Save failed: %v", saveErr)
		} else {
			display.Success("Results saved → %s", outPath)
		}
		display.PrintSectionFooter()
	}

	// ══════════════════════════════════════════════════════
	// Summary
	// ══════════════════════════════════════════════════════
	liveHTTP := 0
	for _, h := range httpResults {
		if h.IsAlive {
			liveHTTP++
		}
	}
	assetCount := 0
	if assetResult != nil {
		assetCount = len(assetResult.MX) + len(assetResult.NS) + len(assetResult.TXT)
	}
	display.PrintStats(cfg.Domain, len(results), liveHTTP, assetCount, time.Since(startTime))
}

// ─── Config ───────────────────────────────────────────────────────────────────

func parseConfig() *Config {
	if len(os.Args) == 1 {
		return interactiveConfig()
	}
	return flagConfig(os.Args[1:])
}

func flagConfig(args []string) *Config {
	cfg := &Config{
		Threads:      50,
		Timeout:      3,
		EnableCT:     true,
		EnableAssets: true,
		OutputFmt:    "json",
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				cfg.Domain = args[i+1]; i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				cfg.Threads, _ = strconv.Atoi(args[i+1]); i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				cfg.OutputFile = args[i+1]; i++
			}
		case "-f", "--format":
			if i+1 < len(args) {
				cfg.OutputFmt = args[i+1]; i++
			}
		case "-w", "--wordlist":
			if i+1 < len(args) {
				cfg.Wordlist = args[i+1]; i++
			}
		case "--timeout":
			if i+1 < len(args) {
				cfg.Timeout, _ = strconv.Atoi(args[i+1]); i++
			}
		case "--http":
			cfg.EnableHTTP = true
		case "--no-ct":
			cfg.EnableCT = false
		case "--osint":
			cfg.EnableOSINT = true
		case "--no-assets":
			cfg.EnableAssets = false
		case "-v", "--verbose":
			cfg.Verbose = true
		case "-h", "--help":
			printHelp()
			os.Exit(0)
		}
	}
	if cfg.Domain == "" {
		display.Error("Domain required. Use -d <domain> or run without args for interactive mode.")
		fmt.Println()
		printHelp()
		os.Exit(1)
	}
	return cfg
}

func interactiveConfig() *Config {
	cfg := &Config{
		Threads:      50,
		Timeout:      3,
		EnableCT:     true,
		EnableAssets: true,
		OutputFmt:    "json",
	}
	reader := bufio.NewReader(os.Stdin)
	display.PrintInteractiveMenu()

	for cfg.Domain == "" {
		display.PrintPrompt("Target Domain", "")
		if input := readLine(reader); input != "" {
			cfg.Domain = strings.ToLower(strings.TrimSpace(input))
		} else {
			display.Warn("Domain cannot be empty.")
		}
	}

	display.PrintPrompt("Threads", "50")
	if t := readLine(reader); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			cfg.Threads = n
		}
	}

	display.PrintPrompt("Enable HTTP probing? (y/n)", "y")
	if yn := strings.ToLower(readLine(reader)); yn != "n" {
		cfg.EnableHTTP = true
	}

	display.PrintPrompt("Enable OSINT sources? (y/n)", "y")
	if yn := strings.ToLower(readLine(reader)); yn != "n" {
		cfg.EnableOSINT = true
	}

	display.PrintPrompt("Custom wordlist path (blank = built-in)", "")
	if wl := readLine(reader); wl != "" {
		cfg.Wordlist = wl
	}

	display.PrintPrompt("Output file (blank to skip)", "results.json")
	if of := readLine(reader); of != "" {
		cfg.OutputFile = of
	}

	if cfg.OutputFile != "" {
		display.PrintPrompt("Output format: json / txt / md", "json")
		if f := strings.ToLower(readLine(reader)); f != "" {
			cfg.OutputFmt = f
		}
	}

	fmt.Println()
	display.Success("Ready — scanning %s", cfg.Domain)
	fmt.Println()
	return cfg
}

func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func printHelp() {
	fmt.Print(`
  SubDiscover v2.0 — Akid's Global Cyber Security Tools © 2026

  USAGE:
    subdiscover                       Interactive guided mode
    subdiscover -d <domain> [flags]   CLI mode

  FLAGS:
    -d / --domain   <domain>   Target domain                    (required)
    -t / --threads  <n>        Worker threads                   (default: 50)
    -o / --output   <file>     Output file path
    -f / --format   <fmt>      Output format: json | txt | md   (default: json)
    -w / --wordlist <file>     Custom wordlist
         --timeout  <sec>      DNS timeout in seconds           (default: 3)
         --http                Enable HTTP/HTTPS probing
         --osint               Enable OSINT sources
         --no-ct               Disable CT log lookup
         --no-assets           Disable DNS asset enumeration
    -v / --verbose             Verbose output
    -h / --help                Show this help

  EXAMPLES:
    subdiscover -d example.com --http --osint -o report.json
    subdiscover -d example.com -t 100 -f md -o report.md --http
    subdiscover -d target.com --no-ct -w wordlist.txt --http

`)
}
