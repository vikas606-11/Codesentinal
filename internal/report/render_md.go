package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// RenderMarkdown renders the report as Markdown. All numbers come from Data.
func RenderMarkdown(d Data) []byte {
	var b strings.Builder
	w := func(f string, a ...any) { b.WriteString(fmt.Sprintf(f, a...)) }

	if d.Watermark != "" {
		w("> **%s**\n\n", d.Watermark)
	}
	title := d.ClientName
	if title == "" {
		title = d.Account
	}
	w("# Security Posture Report — %s\n\n", title)
	w("Prepared by **%s** · %s · scope: %s · status: %s (v%d)\n\n",
		orDash(d.MSPName), d.GeneratedAt.Format("2 Jan 2006"), orDash(d.Scope), d.Status, d.Version)

	w("## Executive summary\n\n%s\n\n", d.Summary)

	w("## Posture score\n\n**%d / 100 — %s**\n\n", d.Score, d.Rating)
	if len(d.Trend) > 0 {
		w("Trend: ")
		var pts []string
		for _, t := range d.Trend {
			pts = append(pts, fmt.Sprintf("%s=%d", t.At.Format("02 Jan"), t.Score))
		}
		w("%s\n\n", strings.Join(pts, ", "))
	}

	w("## What changed since the last scan\n\n")
	w("- New: %d\n- Fixed: %d\n- Regressed: %d\n\n", d.Changes.NewCount, d.Changes.FixedCount, d.Changes.RegressedCount)

	w("## Fix these first\n\n")
	if len(d.TopFixes) == 0 {
		w("No open findings.\n\n")
	} else {
		w("| # | Severity | Risk | Finding | Region | Effort | Owner |\n|---|---|---|---|---|---|---|\n")
		for i, tf := range d.TopFixes {
			effort, owner := "", ""
			if tf.Fix != nil {
				effort = tf.Fix.Effort
			}
			if tf.Finding.Plan != nil {
				owner = tf.Finding.Plan.Owner
			}
			w("| %d | %s | %.0f | %s | %s | %s | %s |\n",
				i+1, tf.Finding.Severity, tf.Finding.RiskScore, mdEsc(tf.Finding.Title), tf.Finding.Region, effort, owner)
		}
		w("\n")
	}

	if len(d.Paths) > 0 {
		w("## Attack paths\n\n")
		for _, p := range d.Paths {
			w("### %s — %s (%s)\n\n", p.Kind, p.Title, p.Severity)
			for _, e := range p.Evidence {
				w("- %s\n", mdEsc(e))
			}
			w("\n**Break the chain:** %s\n\n", mdEsc(p.BreakHint))
		}
	}

	w("## Findings by service\n\n")
	for _, g := range d.ByService {
		w("### %s (%d)\n\n", strings.ToUpper(g.Service), len(g.Findings))
		w("| Severity | Risk | Status | Finding | Source |\n|---|---|---|---|---|\n")
		for _, f := range g.Findings {
			w("| %s | %.0f | %s | %s | %s |\n",
				f.Severity, f.RiskScore, f.Status, mdEsc(f.Title), sourcesStr(f))
		}
		w("\n")
	}

	if len(d.AcceptedRisks) > 0 {
		w("## Accepted risks\n\n| Reason | Owner | Expires |\n|---|---|---|\n")
		for _, r := range d.AcceptedRisks {
			w("| %s | %s | %s |\n", mdEsc(r.Reason), r.Owner, r.ExpiresAt.Format("2 Jan 2006"))
		}
		w("\n")
	}

	if len(d.CIS) > 0 {
		w("## CIS-mapped controls\n\n| Control | Pass | Fail | Accepted |\n|---|---|---|---|\n")
		for _, c := range d.CIS {
			w("| %s | %d | %d | %d |\n", c.Control, c.Pass, c.Fail, c.Accepted)
		}
		w("\n")
	}

	w("## Scope and method\n\n")
	w("- Account: %s\n- Regions: %s\n", orDash(d.Account), strings.Join(d.Regions, ", "))
	for _, s := range d.SourcesRun {
		w("- Source %s: ran=%v count=%d\n", s.Source, s.Ran, s.Count)
	}
	w("- Read-only, point-in-time.\n\n")

	w("## Review record\n\n")
	w("- Reviewer: %s\n- Status: %s\n", orDash(d.Reviewer), d.Status)
	if d.ReviewNote != "" {
		w("- Note: %s\n", mdEsc(d.ReviewNote))
	}
	_ = time.Now
	return []byte(b.String())
}

func sourcesStr(f types.Finding) string {
	var names []string
	for _, s := range f.Sources {
		names = append(names, s.Source)
	}
	if len(names) == 0 {
		return f.Source
	}
	return strings.Join(names, ", ")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
