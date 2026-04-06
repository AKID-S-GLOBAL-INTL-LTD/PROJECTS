package display

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// LiveProgress shows a real-time scanning progress bar
type LiveProgress struct {
	total    int64
	current  int64
	found    int64
	label    string
	stopCh   chan struct{}
	doneCh   chan struct{}
	spinning bool
}

var spinChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func NewProgress(total int, label string) *LiveProgress {
	return &LiveProgress{
		total:  int64(total),
		label:  label,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

func (p *LiveProgress) Inc() {
	atomic.AddInt64(&p.current, 1)
}

func (p *LiveProgress) IncFound() {
	atomic.AddInt64(&p.found, 1)
}

func (p *LiveProgress) Start() {
	go func() {
		defer close(p.doneCh)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		spinIdx := 0
		start := time.Now()

		for {
			select {
			case <-p.stopCh:
				ClearLine()
				return
			case <-ticker.C:
				cur := atomic.LoadInt64(&p.current)
				found := atomic.LoadInt64(&p.found)
				total := atomic.LoadInt64(&p.total)

				pct := 0.0
				if total > 0 {
					pct = float64(cur) / float64(total) * 100
				}
				barWidth := 35
				filled := int(pct / 100 * float64(barWidth))
				bar := BrightGreen + strings.Repeat("█", filled) + Reset +
					Dim + strings.Repeat("░", barWidth-filled) + Reset

				elapsed := time.Since(start).Round(time.Second)
				spin := BrightCyan + spinChars[spinIdx%len(spinChars)] + Reset
				spinIdx++

				fmt.Printf("\r  %s%s%s  [%s] %s%5.1f%%%s  %s%d/%d%s  found:%s%d%s  %s%s%s   ",
					spin, " ", Bold+p.label+Reset,
					bar,
					BrightYellow+Bold, pct, Reset,
					Dim, cur, total, Reset,
					BrightGreen+Bold, found, Reset,
					Dim, elapsed, Reset,
				)
			}
		}
	}()
}

func (p *LiveProgress) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

// SpinnerTask shows a spinner for tasks without a known total
type SpinnerTask struct {
	label  string
	stopCh chan struct{}
	doneCh chan struct{}
}

func NewSpinner(label string) *SpinnerTask {
	return &SpinnerTask{
		label:  label,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

func (s *SpinnerTask) Start() {
	go func() {
		defer close(s.doneCh)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-s.stopCh:
				ClearLine()
				return
			case <-ticker.C:
				spin := BrightMagenta + spinChars[i%len(spinChars)] + Reset
				fmt.Printf("\r  %s  %s%s%s ...", spin, Bold, s.label, Reset)
				i++
			}
		}
	}()
}

func (s *SpinnerTask) Stop(result string) {
	close(s.stopCh)
	<-s.doneCh
	if result != "" {
		fmt.Printf("\r  %s%s[✓]%s  %s: %s%s%s\n", Bold, BrightGreen, Reset, s.label, BrightWhite, result, Reset)
	}
}
