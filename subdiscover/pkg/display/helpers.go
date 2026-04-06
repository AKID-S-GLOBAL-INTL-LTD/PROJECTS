package display

import (
	"fmt"
	"strings"
	"time"
)

const toolWidth = 88

// ─── Shorthand log functions ──────────────────────────────────────────────────

func Info(format string, args ...interface{}) {
	PrintInfo(fmt.Sprintf(format, args...))
}

func Success(format string, args ...interface{}) {
	PrintSuccess(fmt.Sprintf(format, args...))
}

func Warn(format string, args ...interface{}) {
	PrintWarn(fmt.Sprintf(format, args...))
}

func Error(format string, args ...interface{}) {
	PrintError(fmt.Sprintf(format, args...))
}

// ─── Section headers ──────────────────────────────────────────────────────────

func PrintSectionHeader(title string) {
	fmt.Printf("\n  %s%s┌─[ %s%s%s ]%s\n",
		BrightCyan, Bold, BrightWhite, title, BrightCyan, Reset)
}

func PrintSectionFooter() {
	fmt.Printf("  %s└%s%s\n", BrightCyan, strings.Repeat("─", toolWidth-3), Reset)
}

// ─── Result printers ──────────────────────────────────────────────────────────

func PrintSubdomain(idx int, subdomain string, ips []string, isCDN bool, cnames []string) {
	ipStr := strings.Join(ips, ", ")
	cdnTag := ""
	if isCDN {
		cdnTag = BrightMagenta + Bold + " [CDN]" + Reset
	}
	fmt.Printf("  %s│%s  %s%-46s%s  %s%-22s%s%s\n",
		Cyan, Reset,
		BrightWhite, subdomain, Reset,
		Dim, ipStr, Reset,
		cdnTag,
	)
	for _, cname := range cnames {
		fmt.Printf("  %s│%s    %s↳ CNAME: %s%s\n", Cyan, Reset, Dim, cname, Reset)
	}
}

func PrintHTTPResult(subdomain, url, title string, code int, contentLen int64, techs []string) {
	var codeColor string
	switch {
	case code >= 200 && code < 300:
		codeColor = BrightGreen
	case code >= 300 && code < 400:
		codeColor = BrightYellow
	default:
		codeColor = BrightRed
	}
	titleStr := ""
	if title != "" {
		if len(title) > 32 {
			title = title[:29] + "..."
		}
		titleStr = Dim + " \"" + title + "\"" + Reset
	}
	fmt.Printf("  %s│%s  %s%s[%d]%s  %-40s%s\n",
		Cyan, Reset,
		Bold, codeColor, code, Reset,
		BrightWhite+url+Reset,
		titleStr,
	)
	if len(techs) > 0 {
		fmt.Printf("  %s│%s    %s⚙ %s%s\n", Cyan, Reset, Dim, strings.Join(techs, " · "), Reset)
	}
}

func PrintAsset(assetType, value, extra string) {
	var typeColor string
	switch assetType {
	case "MX":
		typeColor = BrightBlue
	case "NS":
		typeColor = BrightGreen
	case "TXT":
		typeColor = Cyan
	case "SOA":
		typeColor = Yellow
	default:
		typeColor = BrightMagenta
	}
	extraStr := ""
	if extra != "" {
		extraStr = "  " + Dim + extra + Reset
	}
	fmt.Printf("  %s│%s  %s%s%-6s%s  %s%s\n",
		Cyan, Reset,
		Bold, typeColor, assetType, Reset,
		BrightWhite+value+Reset,
		extraStr,
	)
}

// ─── Stats summary ────────────────────────────────────────────────────────────

func PrintStats(domain string, subsFound, httpLive, assetsFound int, dur time.Duration) {
	fmt.Println()
	fmt.Printf("  %s%s╔%s╗%s\n", BrightCyan, Bold, strings.Repeat("═", toolWidth-4), Reset)
	title := "  SCAN SUMMARY"
	fmt.Printf("  %s%s║%-*s║%s\n", BrightCyan, Bold, toolWidth-4, title, Reset)
	fmt.Printf("  %s%s╠%s╣%s\n", BrightCyan, Bold, strings.Repeat("═", toolWidth-4), Reset)

	rows := []struct{ label, val string }{
		{"Target", domain},
		{"Subdomains Found", fmt.Sprintf("%s%d%s", BrightGreen+Bold, subsFound, Reset)},
		{"Live HTTP/HTTPS", fmt.Sprintf("%s%d%s", BrightGreen+Bold, httpLive, Reset)},
		{"DNS Assets", fmt.Sprintf("%s%d%s", BrightYellow+Bold, assetsFound, Reset)},
		{"Duration", fmt.Sprintf("%s%s%s", BrightWhite, dur.Round(time.Millisecond), Reset)},
	}
	for _, r := range rows {
		line := fmt.Sprintf("  %-22s: %s", r.label, r.val)
		fmt.Printf("  %s%s║%s %-*s %s║%s\n", BrightCyan, Bold, Reset, toolWidth-6, line, BrightCyan+Bold, Reset)
	}
	fmt.Printf("  %s%s╚%s╝%s\n\n", BrightCyan, Bold, strings.Repeat("═", toolWidth-4), Reset)
}

// ─── Interactive prompts ──────────────────────────────────────────────────────

func PrintInteractiveMenu() {
	fmt.Printf("  %s%s╔%s╗%s\n", BrightMagenta, Bold, strings.Repeat("═", toolWidth-4), Reset)
	fmt.Printf("  %s%s║%-*s║%s\n", BrightMagenta, Bold, toolWidth-4, "  INTERACTIVE SCAN SETUP", Reset)
	fmt.Printf("  %s%s╚%s╝%s\n", BrightMagenta, Bold, strings.Repeat("═", toolWidth-4), Reset)
	fmt.Printf("  %sPress ENTER to accept defaults shown in brackets.%s\n\n", Dim, Reset)
}

func PrintPrompt(label, defaultVal string) {
	if defaultVal != "" {
		fmt.Printf("  %s❯%s  %-30s%s[%s]:%s ", BrightGreen, Reset, label, Dim, defaultVal, Reset)
	} else {
		fmt.Printf("  %s❯%s  %-30s%s:%s ", BrightGreen, Reset, label, Dim, Reset)
	}
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

func PrintProgress(done, total int, label string) {
	if total == 0 {
		return
	}
	pct := float64(done) / float64(total) * 100
	barW := 36
	filled := int(pct / 100 * float64(barW))
	bar := BrightGreen + strings.Repeat("█", filled) + Reset +
		Dim + strings.Repeat("░", barW-filled) + Reset

	fmt.Printf("\r  %s%s[%s] %s%5.1f%%%s  %s%d/%d%s  %s%s%s   ",
		Cyan, Bold,
		bar,
		BrightYellow+Bold, pct, Reset,
		Dim, done, total, Reset,
		Dim, label, Reset,
	)
}
