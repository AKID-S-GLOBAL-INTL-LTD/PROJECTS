package display

import (
	"fmt"
	"strings"
)

// ANSI color codes (no external deps needed for basic colors)
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"

	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	BrightRed     = "\033[91m"
	BrightGreen   = "\033[92m"
	BrightYellow  = "\033[93m"
	BrightBlue    = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan    = "\033[96m"
	BrightWhite   = "\033[97m"

	BgBlue    = "\033[44m"
	BgCyan    = "\033[46m"
	BgMagenta = "\033[45m"
)

const (
	FooterText    = "Akid's Global Cyber Security Tools"
	CopyrightText = "© 2026 Akid's Global Cyber Security Tools. All Rights Reserved."
	ToolVersion   = "v2.0.0"
	ToolName      = "SubDiscover"
)

func PrintBanner() {
	banner := `
` + BrightCyan + Bold + `
  ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ 
  ██╔════╝██║   ██║██╔══██╗██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
  ███████╗██║   ██║██████╔╝██║  ██║██║███████╗██║     ██║   ██║██║   ██║█████╗  ██████╔╝
  ╚════██║██║   ██║██╔══██╗██║  ██║██║╚════██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
  ███████║╚██████╔╝██████╔╝██████╔╝██║███████║╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
` + Reset

	fmt.Print(banner)

	width := 90
	line := strings.Repeat("─", width)

	// Version line
	fmt.Printf("  %s%s%s\n", Dim, line, Reset)
	tagline := fmt.Sprintf("  %s%s Advanced Subdomain & Asset Discovery Framework%s  %s%s%s%s",
		BrightMagenta, Bold, Reset, BrightYellow, Bold, ToolVersion, Reset)
	fmt.Println(tagline)

	// Footer branding
	footerPad := (width - len(FooterText)) / 2
	fmt.Printf("  %s%s%s%s%s\n",
		strings.Repeat(" ", footerPad),
		BrightGreen+Bold, FooterText, Reset, "")

	fmt.Printf("  %s%s%s\n", Dim, line, Reset)
	fmt.Println()
}

func PrintFooter() {
	width := 90
	line := strings.Repeat("═", width)

	fmt.Println()
	fmt.Printf("  %s%s%s\n", BrightCyan, line, Reset)
	fmt.Printf("  %s%s  %-40s%s\n",
		BrightYellow, Bold,
		FooterText,
		Reset,
	)
	fmt.Printf("  %s%s%s\n", Dim, CopyrightText, Reset)
	fmt.Printf("  %s%s%s\n", BrightCyan, line, Reset)
	fmt.Println()
}

func PrintSection(title string) {
	fmt.Printf("\n  %s%s┌─[ %s ]%s\n", BrightCyan, Bold, title, Reset)
}

func PrintInfo(msg string) {
	fmt.Printf("  %s│%s  %s%s[*]%s %s\n", Cyan, Reset, Bold, Blue, Reset, msg)
}

func PrintSuccess(msg string) {
	fmt.Printf("  %s│%s  %s%s[✓]%s %s\n", Cyan, Reset, Bold, BrightGreen, Reset, msg)
}

func PrintWarn(msg string) {
	fmt.Printf("  %s│%s  %s%s[!]%s %s\n", Cyan, Reset, Bold, BrightYellow, Reset, msg)
}

func PrintError(msg string) {
	fmt.Printf("  %s│%s  %s%s[✗]%s %s\n", Cyan, Reset, Bold, BrightRed, Reset, msg)
}

func PrintResult(subdomain string, ips []string, status string, extra string) {
	ipStr := strings.Join(ips, ", ")
	var statusColor string
	switch status {
	case "LIVE":
		statusColor = BrightGreen
	case "DNS":
		statusColor = BrightCyan
	case "ASSET":
		statusColor = BrightMagenta
	default:
		statusColor = Dim
	}
	fmt.Printf("  %s│%s  %s%-6s%s  %-45s  %s%-20s%s  %s\n",
		Cyan, Reset,
		statusColor+Bold, status, Reset,
		BrightWhite+subdomain+Reset,
		Dim, ipStr, Reset,
		Yellow+extra+Reset,
	)
}

func PrintTableHeader() {
	fmt.Printf("  %s│%s  %s%-6s  %-45s  %-20s  %s%s\n",
		Cyan, Reset, Bold+Dim,
		"TYPE", "SUBDOMAIN", "IP(s)", "EXTRA",
		Reset,
	)
	fmt.Printf("  %s│%s  %s%s%s\n", Cyan, Reset, Dim, strings.Repeat("·", 80), Reset)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func ClearLine() {
	fmt.Print("\r\033[K")
}

func PrintSeparator() {
	fmt.Printf("  %s%s%s\n", Dim, strings.Repeat("─", 90), Reset)
}
