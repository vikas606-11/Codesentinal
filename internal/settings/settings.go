// Package settings holds the editable configuration: scoring rubric, branding,
// source toggles, schedule, reviewer, and alert rules (F8, F13). Pure; validated.
package settings

import (
	"fmt"
	"strings"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Weights are the four rubric factor weights (must sum to ~1).
type Weights struct {
	Severity     float64 `json:"severity"`
	Exposure     float64 `json:"exposure"`
	Reachability float64 `json:"reachability"`
	Criticality  float64 `json:"criticality"`
}

// Band maps a minimum score to a rating name.
type Band struct {
	Min  int    `json:"min"`
	Name string `json:"name"`
}

// Rubric is the full scoring configuration.
type Rubric struct {
	Weights        Weights                `json:"weights"`
	Penalty        map[types.Severity]int `json:"penalty"`
	PerSeverityCap map[types.Severity]int `json:"per_severity_cap"`
	Bands          []Band                 `json:"bands"`
}

// Branding is shown in the portal header and on reports.
type Branding struct {
	MSPName     string `json:"msp_name"`
	ClientName  string `json:"client_name"`
	LogoDataURI string `json:"logo_data_uri,omitempty"`
}

// Alerts configures Slack alerting.
type Alerts struct {
	Mode       string          `json:"mode"` // immediate | digest
	WebhookSet bool            `json:"webhook_set"`
	Events     map[string]bool `json:"events"`
}

// Settings is the whole editable configuration.
type Settings struct {
	Branding     Branding        `json:"branding"`
	Sources      map[string]bool `json:"sources"`
	ScanInterval string          `json:"scan_interval"` // 6h | 12h | 24h | off
	Rubric       Rubric          `json:"rubric"`
	Reviewer     string          `json:"reviewer"`
	Alerts       Alerts          `json:"alerts"`
	Paths        map[string]bool `json:"paths"` // AP-1..AP-6 enable flags
}

// Defaults reproduces v1 behaviour.
func Defaults() Settings {
	return Settings{
		Sources:      map[string]bool{"own-check": true, "prowler": true, "scoutsuite": false, "cloudsplaining": false},
		ScanInterval: "6h",
		Rubric: Rubric{
			Weights:        Weights{Severity: 0.40, Exposure: 0.25, Reachability: 0.20, Criticality: 0.15},
			Penalty:        map[types.Severity]int{types.SevCritical: 20, types.SevHigh: 12, types.SevMedium: 5, types.SevLow: 2, types.SevInformational: 0},
			PerSeverityCap: map[types.Severity]int{types.SevCritical: 60, types.SevHigh: 60, types.SevMedium: 40, types.SevLow: 20, types.SevInformational: 0},
			Bands:          []Band{{90, "Excellent"}, {75, "Good"}, {60, "Needs Improvement"}, {0, "Critical"}},
		},
		Alerts: Alerts{Mode: "immediate", Events: map[string]bool{
			"new_critical": true, "new_high": true, "regressed": true,
			"new_path": true, "risk_expiring": true, "scan_failed": true,
		}},
		Paths: map[string]bool{"AP-1": true, "AP-2": true, "AP-3": true, "AP-4": true, "AP-5": true, "AP-6": true},
	}
}

// Validate checks the settings and returns an error describing the first problem.
func (s Settings) Validate() error {
	w := s.Rubric.Weights
	for name, v := range map[string]float64{"severity": w.Severity, "exposure": w.Exposure, "reachability": w.Reachability, "criticality": w.Criticality} {
		if v < 0 || v > 1 {
			return fmt.Errorf("weight %s must be in [0,1]", name)
		}
	}
	sum := w.Severity + w.Exposure + w.Reachability + w.Criticality
	if sum < 0.999 || sum > 1.001 {
		return fmt.Errorf("weights must sum to 1, got %.3f", sum)
	}
	for sev, p := range s.Rubric.Penalty {
		if p < 0 || p > 50 {
			return fmt.Errorf("penalty for %s must be 0..50", sev)
		}
	}
	for sev, c := range s.Rubric.PerSeverityCap {
		if c < 0 {
			return fmt.Errorf("cap for %s must be >= 0", sev)
		}
	}
	switch s.ScanInterval {
	case "", "6h", "12h", "24h", "off":
	default:
		return fmt.Errorf("scan_interval must be 6h, 12h, 24h or off")
	}
	if s.Alerts.Mode != "" && s.Alerts.Mode != "immediate" && s.Alerts.Mode != "digest" {
		return fmt.Errorf("alerts.mode must be immediate or digest")
	}
	return nil
}

// ChangedKeys returns the top-level keys that differ (for an audit diff without
// leaking secret values).
func ChangedKeys(a, b Settings) []string {
	var keys []string
	if a.Branding != b.Branding {
		keys = append(keys, "branding")
	}
	if a.ScanInterval != b.ScanInterval {
		keys = append(keys, "scan_interval")
	}
	if a.Reviewer != b.Reviewer {
		keys = append(keys, "reviewer")
	}
	if fmt.Sprint(a.Rubric) != fmt.Sprint(b.Rubric) {
		keys = append(keys, "rubric")
	}
	if fmt.Sprint(a.Sources) != fmt.Sprint(b.Sources) {
		keys = append(keys, "sources")
	}
	if fmt.Sprint(a.Alerts.Events) != fmt.Sprint(b.Alerts.Events) || a.Alerts.Mode != b.Alerts.Mode {
		keys = append(keys, "alerts")
	}
	if fmt.Sprint(a.Paths) != fmt.Sprint(b.Paths) {
		keys = append(keys, "paths")
	}
	return keys
}

// ValidateLogo checks a data URI is a small PNG/JPEG (not SVG). Returns decoded size.
func ValidateLogo(dataURI string) error {
	if dataURI == "" {
		return nil
	}
	if !strings.HasPrefix(dataURI, "data:image/png") && !strings.HasPrefix(dataURI, "data:image/jpeg") && !strings.HasPrefix(dataURI, "data:image/jpg") {
		return fmt.Errorf("logo must be a PNG or JPEG data URI")
	}
	return nil
}
