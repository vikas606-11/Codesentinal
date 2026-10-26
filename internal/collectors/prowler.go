// Package collectors — Prowler collector.
//
// Prowler (https://github.com/prowler-cloud/prowler) is the open-source,
// read-only AWS security scanner CodeSentinal. delegates broad check coverage to
// (CIS / AWS FSBP, hundreds of controls). It runs as a separate Kubernetes
// CronJob under the same read-only IRSA role and writes OCSF JSON to a shared
// results directory. This collector ingests that JSON — it never runs scans
// itself and never mutates AWS.
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

// ProwlerCollector reads Prowler OCSF JSON results from a directory.
type ProwlerCollector struct {
	resultsDir string
	accountID  string
	region     string
}

func NewProwlerCollector(resultsDir, accountID, region string) *ProwlerCollector {
	return &ProwlerCollector{resultsDir: resultsDir, accountID: accountID, region: region}
}

func (p *ProwlerCollector) Name() string { return "prowler" }

// ocsfFinding is the subset of Prowler's OCSF Detection Finding we use.
// Matches Prowler 5.x OCSF 1.x output.
type ocsfFinding struct {
	StatusCode string `json:"status_code"` // PASS | FAIL | MANUAL
	Severity   string `json:"severity"`    // Critical/High/Medium/Low/Informational
	Message    string `json:"message"`
	Metadata   struct {
		EventCode string `json:"event_code"` // the prowler check id
	} `json:"metadata"`
	FindingInfo struct {
		Title string `json:"title"`
		UID   string `json:"uid"`
		Desc  string `json:"desc"`
	} `json:"finding_info"`
	Resources []struct {
		UID   string `json:"uid"`
		Name  string `json:"name"`
		Type  string `json:"type"`
		Group struct {
			Name string `json:"name"`
		} `json:"group"`
		Region string `json:"region"`
	} `json:"resources"`
	Remediation struct {
		Desc string `json:"desc"`
	} `json:"remediation"`
	Unmapped struct {
		Categories  []string `json:"categories"`
		ServiceName string   `json:"service_name"`
	} `json:"unmapped"`
	Cloud struct {
		Region  string `json:"region"`
		Account struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
}

// Collect reads the latest Prowler OCSF file and returns FAIL findings.
// A missing directory or file is NOT an error — it yields a warning so the
// product still works before the first scan completes.
func (p *ProwlerCollector) Collect(ctx context.Context) ([]types.Finding, []string) {
	path, err := p.latestOCSF()
	if err != nil {
		return nil, []string{fmt.Sprintf("prowler: %v (offline until first scan completes)", err)}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("prowler: read %s: %v", path, err)}
	}

	items, perr := parseOCSF(raw)
	if len(items) == 0 {
		if perr != nil {
			return nil, []string{fmt.Sprintf("prowler: parse %s: %v", path, perr)}
		}
		return nil, []string{"prowler: results file had no findings"}
	}

	var findings []types.Finding
	for _, it := range items {
		if !strings.EqualFold(it.StatusCode, "FAIL") {
			continue // only surface failing controls
		}
		findings = append(findings, p.toFinding(it))
	}
	return findings, nil
}

func (p *ProwlerCollector) toFinding(it ocsfFinding) types.Finding {
	sev := normalizeSeverity(it.Severity)

	checkID := it.Metadata.EventCode
	service := strings.ToLower(it.Unmapped.ServiceName)
	if service == "" && checkID != "" {
		// Prowler check ids are "<service>_<rest>", e.g. "s3_bucket_public".
		if i := strings.Index(checkID, "_"); i > 0 {
			service = checkID[:i]
		}
	}
	resourceID, region := p.accountID, p.region
	public := false
	if len(it.Resources) > 0 {
		r := it.Resources[0]
		if r.UID != "" {
			resourceID = r.UID
		} else if r.Name != "" {
			resourceID = r.Name
		}
		if r.Region != "" {
			region = r.Region
		}
		if service == "" && r.Group.Name != "" {
			service = strings.ToLower(r.Group.Name)
		}
	}
	if it.Cloud.Region != "" {
		region = it.Cloud.Region
	}
	if service == "" {
		service = "aws"
	}

	title := it.FindingInfo.Title
	if title == "" {
		title = it.Message
	}
	desc := it.FindingInfo.Desc
	if desc == "" {
		desc = it.Message
	}
	rec := it.Remediation.Desc
	if rec == "" {
		rec = "See the linked control's remediation guidance."
	}

	// Public exposure heuristic from the check id / title.
	hay := strings.ToLower(checkID + " " + title + " " + it.Message)
	if strings.Contains(hay, "public") || strings.Contains(hay, "0.0.0.0/0") ||
		strings.Contains(hay, "internet") || strings.Contains(hay, "exposed") {
		public = true
	}

	normID := fingerprint.NormaliseResourceID(service, resourceID, region, p.accountID)
	canon := fingerprint.Canonical("prowler", checkID)
	fp := fingerprint.Of(p.accountID, service, region, normID, canon)
	return types.Finding{
		ID:               fp,
		Fingerprint:      fp,
		CanonicalKey:     canon,
		CheckID:          checkID,
		Source:           "prowler",
		NativeSeverity:   it.Severity,
		Severity:         sev,
		Service:          service,
		ResourceID:       normID,
		Region:           region,
		AccountID:        p.accountID,
		Title:            title,
		Description:      desc,
		Recommendation:   rec,
		FrameworkControl: checkID,
		Factors:          ranking.DefaultFactors(sev, service, public, true),
		Sources:          []types.SourceRef{{Source: "prowler", CheckID: checkID, NativeSeverity: it.Severity}},
	}
}

// latestOCSF returns the newest *.ocsf.json (or *.json) file in resultsDir.
func (p *ProwlerCollector) latestOCSF() (string, error) {
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
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// Prefer OCSF output files.
		cands = append(cands, cand{filepath.Join(p.resultsDir, name), info.ModTime()})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no JSON results found yet")
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	// Prefer a file with "ocsf" in the name if present.
	for _, c := range cands {
		if strings.Contains(strings.ToLower(c.path), "ocsf") {
			return c.path, nil
		}
	}
	return cands[0].path, nil
}

// parseOCSF robustly decodes Prowler OCSF output. It handles:
//   - a single JSON array of findings
//   - multiple concatenated JSON arrays (Prowler can append across runs)
//   - newline-delimited JSON objects
//
// by streaming successive JSON values from the input.
func parseOCSF(raw []byte) ([]ocsfFinding, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	var out []ocsfFinding
	var lastErr error
	for {
		// Peek at the next value as RawMessage so one bad value doesn't abort all.
		var msg json.RawMessage
		if err := dec.Decode(&msg); err != nil {
			if err.Error() == "EOF" {
				break
			}
			lastErr = err
			break
		}
		trimmed := strings.TrimSpace(string(msg))
		if strings.HasPrefix(trimmed, "[") {
			// An array of findings.
			var arr []ocsfFinding
			if err := json.Unmarshal(msg, &arr); err != nil {
				lastErr = err
				continue
			}
			out = append(out, arr...)
		} else if strings.HasPrefix(trimmed, "{") {
			// A single finding object.
			var one ocsfFinding
			if err := json.Unmarshal(msg, &one); err != nil {
				lastErr = err
				continue
			}
			out = append(out, one)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	return out, lastErr
}

func normalizeSeverity(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return types.SevCritical
	case "HIGH":
		return types.SevHigh
	case "MEDIUM":
		return types.SevMedium
	case "LOW":
		return types.SevLow
	default:
		return types.SevInformational
	}
}
