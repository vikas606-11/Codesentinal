// Package report builds report data from a review and renders it to Markdown,
// HTML and DOCX (F9), with a draft/review/approve workflow (F10). Pure, stdlib
// only. All numbers come from the input data; renderers do no arithmetic.
package report

import (
	"sort"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/fixes"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Data is everything a renderer needs. Build it once and snapshot it so an
// approved report renders identically later.
type Data struct {
	MSPName     string    `json:"msp_name"`
	ClientName  string    `json:"client_name"`
	LogoDataURI string    `json:"logo_data_uri,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	Scope       string    `json:"scope"`
	Status      string    `json:"status"`
	Version     int       `json:"version"`
	Watermark   string    `json:"watermark,omitempty"` // "DRAFT, not reviewed" when not approved

	Account string   `json:"account"`
	Regions []string `json:"regions"`

	Score     int    `json:"score"`
	Rating    string `json:"rating"`
	PrevScore *int   `json:"prev_score,omitempty"`
	Summary   string `json:"summary"`

	Trend   []TrendPoint  `json:"trend"`
	Changes types.Changes `json:"changes"`

	TopFixes      []TopFix             `json:"top_fixes"`
	Paths         []types.AttackPath   `json:"paths"`
	ByService     []ServiceGroup       `json:"by_service"`
	AcceptedRisks []types.AcceptedRisk `json:"accepted_risks"`
	CIS           []CISRow             `json:"cis"`

	SourcesRun []SourceRunInfo `json:"sources_run"`
	Reviewer   string          `json:"reviewer"`
	ReviewNote string          `json:"review_note,omitempty"`
}

type TrendPoint struct {
	At    time.Time `json:"at"`
	Score int       `json:"score"`
}
type TopFix struct {
	Finding types.Finding `json:"finding"`
	Fix     *fixes.Fix    `json:"fix,omitempty"`
}
type ServiceGroup struct {
	Service  string          `json:"service"`
	Findings []types.Finding `json:"findings"`
}
type CISRow struct {
	Control  string `json:"control"`
	Pass     int    `json:"pass"`
	Fail     int    `json:"fail"`
	Accepted int    `json:"accepted"`
}
type SourceRunInfo struct {
	Source string    `json:"source"`
	Ran    bool      `json:"ran"`
	At     time.Time `json:"at"`
	Count  int       `json:"count"`
}

// BuildInput bundles everything Build needs.
type BuildInput struct {
	Review      *types.PostureReview
	History     []types.HistoryPoint
	Risks       []types.AcceptedRisk
	MSPName     string
	ClientName  string
	LogoDataURI string
	Reviewer    string
	Scope       string // account | service:<k> | resource:<id>
}

// Build produces report Data. Pure.
func Build(in BuildInput) Data {
	rv := in.Review
	d := Data{
		MSPName: in.MSPName, ClientName: in.ClientName, LogoDataURI: in.LogoDataURI,
		GeneratedAt: time.Now().UTC(), Scope: in.Scope, Status: "draft", Version: 1,
		Reviewer: in.Reviewer,
	}
	if rv == nil {
		d.Summary = "No review data available yet."
		return d
	}
	d.Account = rv.AccountID
	d.Regions = rv.Regions
	d.Score = rv.PostureScore
	d.Rating = rv.Rating
	d.Changes = rv.Changes
	d.Paths = rv.Paths

	// filter findings by scope
	findings := scopeFindings(rv.Findings, in.Scope)

	// trend
	for _, h := range in.History {
		d.Trend = append(d.Trend, TrendPoint{At: h.At, Score: h.Score})
	}
	if len(in.History) >= 2 {
		prev := in.History[len(in.History)-2].Score
		d.PrevScore = &prev
	}

	// top fixes (top 10 by risk, open/regressed only)
	ranked := append([]types.Finding(nil), findings...)
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].RiskScore > ranked[j].RiskScore })
	for _, f := range ranked {
		if f.Status == types.StatusFixed || f.Status == types.StatusAccepted {
			continue
		}
		tf := TopFix{Finding: f}
		if fx, ok := fixes.For(f); ok {
			tf.Fix = &fx
		}
		d.TopFixes = append(d.TopFixes, tf)
		if len(d.TopFixes) >= 10 {
			break
		}
	}

	// group by service
	bySvc := map[string][]types.Finding{}
	var svcOrder []string
	for _, f := range findings {
		if _, ok := bySvc[f.Service]; !ok {
			svcOrder = append(svcOrder, f.Service)
		}
		bySvc[f.Service] = append(bySvc[f.Service], f)
	}
	sort.Strings(svcOrder)
	for _, svc := range svcOrder {
		group := bySvc[svc]
		sort.SliceStable(group, func(i, j int) bool { return group[i].RiskScore > group[j].RiskScore })
		d.ByService = append(d.ByService, ServiceGroup{Service: svc, Findings: group})
	}

	// accepted risks
	d.AcceptedRisks = in.Risks

	// CIS mapping from framework control
	d.CIS = buildCIS(findings)

	// sources run
	for src, st := range rv.SourcesStatus {
		d.SourcesRun = append(d.SourcesRun, SourceRunInfo{Source: src, Ran: st.Ran, At: st.At, Count: st.Count})
	}
	sort.SliceStable(d.SourcesRun, func(i, j int) bool { return d.SourcesRun[i].Source < d.SourcesRun[j].Source })

	d.Summary = buildSummary(d)
	return d
}

func scopeFindings(fs []types.Finding, scope string) []types.Finding {
	if scope == "" || scope == "account" {
		return fs
	}
	var out []types.Finding
	if len(scope) > 8 && scope[:8] == "service:" {
		svc := scope[8:]
		for _, f := range fs {
			if f.Service == svc {
				out = append(out, f)
			}
		}
		return out
	}
	if len(scope) > 9 && scope[:9] == "resource:" {
		rid := scope[9:]
		for _, f := range fs {
			if f.ResourceID == rid {
				out = append(out, f)
			}
		}
		return out
	}
	return fs
}

func buildCIS(fs []types.Finding) []CISRow {
	rows := map[string]*CISRow{}
	var order []string
	for _, f := range fs {
		ctrl := f.FrameworkControl
		if ctrl == "" || !isCIS(ctrl) {
			continue
		}
		r, ok := rows[ctrl]
		if !ok {
			r = &CISRow{Control: ctrl}
			rows[ctrl] = r
			order = append(order, ctrl)
		}
		switch f.Status {
		case types.StatusAccepted:
			r.Accepted++
		default:
			r.Fail++
		}
	}
	sort.Strings(order)
	var out []CISRow
	for _, c := range order {
		out = append(out, *rows[c])
	}
	return out
}

func isCIS(ctrl string) bool {
	return len(ctrl) >= 3 && (ctrl[:3] == "CIS" || ctrl[:3] == "cis")
}

func countBySeverity(fs []types.Finding) map[types.Severity]int {
	m := map[types.Severity]int{}
	for _, f := range fs {
		if f.Status == types.StatusFixed || f.Status == types.StatusAccepted {
			continue
		}
		m[f.Severity]++
	}
	return m
}
