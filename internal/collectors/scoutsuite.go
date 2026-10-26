// Package collectors — ScoutSuite collector.
//
// ScoutSuite (https://github.com/nccgroup/ScoutSuite) is an open-source,
// read-only multi-cloud posture auditor. It runs as a separate Kubernetes
// Job under the read-only IRSA role and writes a results file. ScoutSuite's
// default output is a JS file (scoutsuite_results_aws-*.js) that begins with
// "scoutsuite_results =" followed by a JSON object. This collector strips that
// prefix and ingests the findings, normalizing them into types.Finding.
//
// Like Prowler, it never runs scans itself and never mutates AWS.
package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/fingerprint"
	"github.com/sriramg-aivar/CodeSentinal./internal/ranking"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// slug makes a short stable key fragment from a title.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteRune('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// ScoutSuiteCollector reads ScoutSuite results from a directory.
type ScoutSuiteCollector struct {
	resultsDir string
	accountID  string
	region     string
}

func NewScoutSuiteCollector(resultsDir, accountID, region string) *ScoutSuiteCollector {
	return &ScoutSuiteCollector{resultsDir: resultsDir, accountID: accountID, region: region}
}

func (p *ScoutSuiteCollector) Name() string { return "scoutsuite" }

// scoutResults is the subset of ScoutSuite's JSON we consume.
type scoutResults struct {
	Services map[string]struct {
		Findings map[string]struct {
			Description string   `json:"description"`
			Rationale   string   `json:"rationale"`
			Remediation string   `json:"remediation"`
			Level       string   `json:"level"` // danger | warning
			Flagged     int      `json:"flagged_items"`
			Items       []string `json:"items"`
		} `json:"findings"`
	} `json:"services"`
}

// Collect reads the latest ScoutSuite results file and returns flagged findings.
func (p *ScoutSuiteCollector) Collect(ctx context.Context) ([]types.Finding, []string) {
	path, err := p.latestResults()
	if err != nil {
		return nil, []string{fmt.Sprintf("scoutsuite: %v (offline until first scan completes)", err)}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("scoutsuite: read %s: %v", path, err)}
	}
	jsonBytes := stripScoutPrefix(raw)

	var res scoutResults
	if err := json.Unmarshal(jsonBytes, &res); err != nil {
		return nil, []string{fmt.Sprintf("scoutsuite: parse %s: %v", path, err)}
	}

	var findings []types.Finding
	for svcName, svc := range res.Services {
		for _, f := range svc.Findings {
			if f.Flagged == 0 && len(f.Items) == 0 {
				continue // only surface flagged findings
			}
			sev := scoutLevelToSeverity(f.Level)
			title := f.Description
			if title == "" {
				title = fmt.Sprintf("%s finding", strings.ToUpper(svcName))
			}
			rec := f.Remediation
			if rec == "" {
				rec = "Review the ScoutSuite rationale and apply least-privilege / hardening."
			}
			public := strings.Contains(strings.ToLower(title+f.Rationale), "public") ||
				strings.Contains(strings.ToLower(title+f.Rationale), "0.0.0.0/0")
			resourceID := p.accountID
			if len(f.Items) > 0 {
				resourceID = f.Items[0]
			}
			svc := strings.ToLower(svcName)
			checkID := "scout-" + svc + "-" + slug(title)
			normID := fingerprint.NormaliseResourceID(svc, resourceID, p.region, p.accountID)
			canon := fingerprint.Canonical("scoutsuite", checkID)
			fp := fingerprint.Of(p.accountID, svc, p.region, normID, canon)
			findings = append(findings, types.Finding{
				ID:             fp,
				Fingerprint:    fp,
				CanonicalKey:   canon,
				CheckID:        checkID,
				Source:         "scoutsuite",
				NativeSeverity: f.Level,
				Severity:       sev,
				Service:        svc,
				ResourceID:     normID,
				Region:         p.region,
				AccountID:      p.accountID,
				Title:          title,
				Description:    f.Rationale,
				Recommendation: rec,
				Factors:        ranking.DefaultFactors(sev, svc, public, true),
				Sources:        []types.SourceRef{{Source: "scoutsuite", CheckID: checkID, NativeSeverity: f.Level}},
			})
		}
	}
	return findings, nil
}

func (p *ScoutSuiteCollector) latestResults() (string, error) {
	if p.resultsDir == "" {
		return "", fmt.Errorf("no results dir configured")
	}
	entries, err := os.ReadDir(p.resultsDir)
	if err != nil {
		return "", fmt.Errorf("results dir %s: %w", p.resultsDir, err)
	}
	type cand struct {
		path string
		mod  time.Time
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.Contains(name, "scoutsuite_results") {
			continue
		}
		if info, err := e.Info(); err == nil {
			cands = append(cands, cand{filepath.Join(p.resultsDir, e.Name()), info.ModTime()})
		}
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no scoutsuite results found yet")
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	return cands[0].path, nil
}

// stripScoutPrefix removes the "scoutsuite_results =" JS assignment prefix (and
// a trailing semicolon) if present, returning raw JSON.
func stripScoutPrefix(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))
	if i := strings.Index(s, "="); i >= 0 && strings.HasPrefix(s, "scoutsuite_results") {
		s = strings.TrimSpace(s[i+1:])
	}
	s = strings.TrimSuffix(s, ";")
	return []byte(s)
}

func scoutLevelToSeverity(level string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "danger":
		return types.SevHigh
	case "warning":
		return types.SevMedium
	default:
		return types.SevLow
	}
}
