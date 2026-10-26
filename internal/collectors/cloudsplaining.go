// Package collectors — cloudsplaining collector.
//
// cloudsplaining (https://github.com/salvo-ops/cloudsplaining) is an
// open-source, read-only IAM policy risk scanner: it flags privilege
// escalation, data-exfiltration, resource-exposure and credential-exposure
// risks in IAM policies. It runs as a Kubernetes Job under the read-only IRSA
// role (it only needs iam:Get*/List* to download the authorization details)
// and writes a JSON findings file this collector ingests.
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

// CloudsplainingCollector reads cloudsplaining JSON results from a directory.
type CloudsplainingCollector struct {
	resultsDir string
	accountID  string
	region     string
}

func NewCloudsplainingCollector(resultsDir, accountID, region string) *CloudsplainingCollector {
	return &CloudsplainingCollector{resultsDir: resultsDir, accountID: accountID, region: region}
}

func (p *CloudsplainingCollector) Name() string { return "cloudsplaining" }

// csResults maps the cloudsplaining JSON findings we consume. cloudsplaining's
// schema varies by version; we read the common "results" map of principals ->
// risk buckets, plus a flattened fallback.
type csEntry struct {
	PolicyName            string   `json:"PolicyName"`
	PrivilegeEscalation   []any    `json:"PrivilegeEscalation"`
	DataExfiltration      []string `json:"DataExfiltrationActions"`
	ResourceExposure      []string `json:"ResourceExposureActions"`
	CredentialsExposure   []string `json:"CredentialsExposureActions"`
	PermissionsManagement []string `json:"PermissionsManagementActions"`
}

func (p *CloudsplainingCollector) Collect(ctx context.Context) ([]types.Finding, []string) {
	path, err := p.latestResults()
	if err != nil {
		return nil, []string{fmt.Sprintf("cloudsplaining: %v (offline until first scan completes)", err)}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("cloudsplaining: read %s: %v", path, err)}
	}

	// results is a map keyed by policy id -> csEntry.
	var wrapper struct {
		Results map[string]csEntry `json:"results"`
	}
	entries := map[string]csEntry{}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Results) > 0 {
		entries = wrapper.Results
	} else {
		// Fallback: top-level map of id -> entry.
		_ = json.Unmarshal(raw, &entries)
	}
	if len(entries) == 0 {
		return nil, []string{"cloudsplaining: no IAM policy risks parsed"}
	}

	var findings []types.Finding
	for id, e := range entries {
		name := e.PolicyName
		if name == "" {
			name = id
		}
		add := func(sev types.Severity, risk string, actions []string) {
			if len(actions) == 0 {
				return
			}
			checkID := "cloudsplaining-" + strings.ReplaceAll(strings.ToLower(risk), " ", "-")
			normID := fingerprint.NormaliseResourceID("iam", name, "global", p.accountID)
			canon := fingerprint.Canonical("cloudsplaining", checkID)
			fp := fingerprint.Of(p.accountID, "iam", "global", normID, canon)
			findings = append(findings, types.Finding{
				ID:               fp,
				Fingerprint:      fp,
				CanonicalKey:     canon,
				CheckID:          checkID,
				Source:           "cloudsplaining",
				NativeSeverity:   string(sev),
				Severity:         sev,
				Service:          "iam",
				ResourceID:       normID,
				Region:           "global",
				AccountID:        p.accountID,
				Title:            fmt.Sprintf("IAM policy '%s' allows %s", name, risk),
				Description:      fmt.Sprintf("%d risky action(s): %s", len(actions), strings.Join(firstN(actions, 5), ", ")),
				Recommendation:   "Scope this policy down; remove the risky actions or restrict resources/conditions.",
				FrameworkControl: checkID,
				Factors:          ranking.DefaultFactors(sev, "iam", false, true),
				Sources:          []types.SourceRef{{Source: "cloudsplaining", CheckID: checkID}},
			})
		}
		if len(e.PrivilegeEscalation) > 0 {
			checkID := "cloudsplaining-privilege-escalation"
			normID := fingerprint.NormaliseResourceID("iam", name, "global", p.accountID)
			canon := fingerprint.Canonical("cloudsplaining", checkID)
			fp := fingerprint.Of(p.accountID, "iam", "global", normID, canon)
			findings = append(findings, types.Finding{
				ID: fp, Fingerprint: fp, CanonicalKey: canon, CheckID: checkID,
				Source: "cloudsplaining", NativeSeverity: "CRITICAL",
				Severity: types.SevCritical, Service: "iam", ResourceID: normID, Region: "global",
				AccountID:        p.accountID,
				Title:            fmt.Sprintf("IAM policy '%s' enables privilege escalation", name),
				Description:      fmt.Sprintf("%d privilege-escalation path(s) detected.", len(e.PrivilegeEscalation)),
				Recommendation:   "Remove the actions that allow escalation (e.g. iam:PassRole + create/update).",
				FrameworkControl: checkID,
				Factors:          ranking.DefaultFactors(types.SevCritical, "iam", false, true),
				Sources:          []types.SourceRef{{Source: "cloudsplaining", CheckID: checkID}},
			})
		}
		add(types.SevHigh, "data exfiltration", e.DataExfiltration)
		add(types.SevHigh, "resource exposure", e.ResourceExposure)
		add(types.SevHigh, "credentials exposure", e.CredentialsExposure)
		add(types.SevMedium, "permissions management", e.PermissionsManagement)
	}
	return findings, nil
}

func (p *CloudsplainingCollector) latestResults() (string, error) {
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
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		if info, err := e.Info(); err == nil {
			cands = append(cands, cand{filepath.Join(p.resultsDir, e.Name()), info.ModTime()})
		}
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no cloudsplaining results found yet")
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	return cands[0].path, nil
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
