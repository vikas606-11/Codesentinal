// Package types defines the core domain model shared across CodeSentinal..
package types

import "time"

// Severity levels, normalized across all sources.
type Severity string

const (
	SevCritical      Severity = "CRITICAL"
	SevHigh          Severity = "HIGH"
	SevMedium        Severity = "MEDIUM"
	SevLow           Severity = "LOW"
	SevInformational Severity = "INFORMATIONAL"
)

// Status is a finding's lifecycle state (F1).
type Status string

const (
	StatusOpen      Status = "open"
	StatusFixed     Status = "fixed"
	StatusRegressed Status = "regressed"
	StatusAccepted  Status = "accepted"
)

// Resource is one discovered AWS resource, grouped by service in the dashboard.
type Resource struct {
	ID        string            `json:"id"`      // ARN or unique id
	Service   string            `json:"service"` // ec2, s3, iam, rds, lambda, dynamodb, ecs, eks, cloudtrail
	Type      string            `json:"type"`    // e.g. "instance", "bucket", "role", "trail", "security-group", "volume"
	Name      string            `json:"name"`    // human-friendly name
	Region    string            `json:"region"`  // "global" for IAM
	AccountID string            `json:"account_id"`
	Tags      map[string]string `json:"tags,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"` // facts the UI needs (public_ip, state, engine, multi_region...)
}

// RiskFactors are the four rubric inputs (each 0..1).
type RiskFactors struct {
	Severity            float64 `json:"severity"`
	Exposure            float64 `json:"exposure"`
	Reachability        float64 `json:"reachability"`
	ResourceCriticality float64 `json:"resource_criticality"`
}

// SourceRef records one source that reported a (possibly deduplicated) finding.
type SourceRef struct {
	Source         string `json:"source"` // own-check | prowler | scoutsuite | cloudsplaining | (paid) securityhub...
	NativeID       string `json:"native_id,omitempty"`
	NativeSeverity string `json:"native_severity,omitempty"`
	CheckID        string `json:"check_id,omitempty"`
}

// Plan is the remediation plan attached to a finding (F5).
type Plan struct {
	Owner     string    `json:"owner"`
	Effort    string    `json:"effort"` // "S" | "M" | "L" | ""
	DueDate   *string   `json:"due_date"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AcceptedRisk is an accepted-risk register entry (F4).
type AcceptedRisk struct {
	Fingerprint string    `json:"fingerprint"`
	Reason      string    `json:"reason"`
	Owner       string    `json:"owner"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// Finding is one normalized security finding on a resource.
type Finding struct {
	ID               string      `json:"id"` // == Fingerprint, stable across scans
	Source           string      `json:"source"`
	NativeSeverity   string      `json:"native_severity"`
	Severity         Severity    `json:"severity"`
	RiskScore        float64     `json:"risk_score"`
	Service          string      `json:"service"`
	ResourceID       string      `json:"resource_id"`
	Region           string      `json:"region"`
	AccountID        string      `json:"account_id"`
	Title            string      `json:"title"`
	Description      string      `json:"description"`
	Recommendation   string      `json:"recommendation"`
	FrameworkControl string      `json:"framework_control,omitempty"`
	Factors          RiskFactors `json:"factors"`

	// v2 additions (F1, F2).
	Fingerprint  string            `json:"fingerprint"`
	CanonicalKey string            `json:"canonical_key"`
	CheckID      string            `json:"check_id"`
	Sources      []SourceRef       `json:"sources,omitempty"`
	Status       Status            `json:"status"`
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
	FixedAt      *time.Time        `json:"fixed_at,omitempty"`
	RegressedAt  *time.Time        `json:"regressed_at,omitempty"`
	AgeDays      int               `json:"age_days"`
	OnPath       []string          `json:"on_path,omitempty"`
	Plan         *Plan             `json:"plan,omitempty"`
	Accepted     *AcceptedRisk     `json:"accepted,omitempty"`
	Attrs        map[string]string `json:"attrs,omitempty"` // CVE etc. (paid)
}

// PathStep is one node in an attack path.
type PathStep struct {
	Label      string `json:"label"`
	ResourceID string `json:"resource_id"`
	Detail     string `json:"detail"`
}

// AttackPath is a chain of conditions that together create real risk (F6).
type AttackPath struct {
	ID         string     `json:"id"`   // "AP-1:<resource>"
	Kind       string     `json:"kind"` // AP-1..AP-6
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Score      float64    `json:"score"`
	Steps      []PathStep `json:"steps"`
	Evidence   []string   `json:"evidence"`
	BreakAt    int        `json:"break_at"`
	BreakHint  string     `json:"break_hint"`
	FindingIDs []string   `json:"finding_ids"`
	Signals    []string   `json:"signals,omitempty"` // paid: known-exploit CVE, active threat
}

// HistoryPoint is one trend data point, saved after each full scan (F3).
type HistoryPoint struct {
	At         time.Time      `json:"at"`
	ReviewID   string         `json:"review_id"`
	Score      int            `json:"score"`
	Rating     string         `json:"rating"`
	Open       int            `json:"open"`
	BySeverity map[string]int `json:"by_severity"`
	New        int            `json:"new"`
	Fixed      int            `json:"fixed"`
	Regressed  int            `json:"regressed"`
	Accepted   int            `json:"accepted"`
}

// Changes summarises what changed between two scans (F3).
type Changes struct {
	New            []string `json:"new"`
	Fixed          []string `json:"fixed"`
	Regressed      []string `json:"regressed"`
	NewCount       int      `json:"new_count"`
	FixedCount     int      `json:"fixed_count"`
	RegressedCount int      `json:"regressed_count"`
}

// SourceStatus records whether a source ran in a scan (used by lifecycle).
type SourceStatus struct {
	Ran   bool      `json:"ran"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
	Count int       `json:"count"`
}

// Explanation is the AI/offline explanation of a finding.
type Explanation struct {
	Problem      string    `json:"problem"`
	WhyDangerous string    `json:"why_dangerous"`
	Impact       string    `json:"impact"`
	HowToFix     []string  `json:"how_to_fix"`
	ConsolePath  string    `json:"aws_console_path"`
	Provider     string    `json:"provider"` // bedrock | offline
	Model        string    `json:"model"`
	Note         string    `json:"note,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// PostureSummary aggregates counts for the dashboard.
type PostureSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByService  map[string]int `json:"by_service"`
	BySource   map[string]int `json:"by_source"`
}

// PostureReview is the full output of one review run.
type PostureReview struct {
	ReviewID        string           `json:"review_id"`
	AccountID       string           `json:"account_id"`
	Regions         []string         `json:"regions"`
	Status          string           `json:"status"`
	CreatedAt       time.Time        `json:"created_at"`
	DurationSeconds float64          `json:"duration_seconds"`
	PostureScore    int              `json:"posture_score"`
	Rating          string           `json:"rating"`
	Summary         PostureSummary   `json:"summary"`
	Findings        []Finding        `json:"findings"`
	Resources       []Resource       `json:"resources"`
	SourcesRun      []string         `json:"sources_run"`
	CollectorErrors []CollectorError `json:"collector_errors"`
	Warnings        []string         `json:"warnings"`

	// v2 additions.
	Paths            []AttackPath            `json:"paths,omitempty"`
	Changes          Changes                 `json:"changes"`
	SourcesStatus    map[string]SourceStatus `json:"sources_status,omitempty"`
	DuplicatesMerged int                     `json:"duplicates_merged"`
	Scope            string                  `json:"scope,omitempty"` // "", "service:ec2", "resource:<id>"
}

// CollectorError records a source that could not run.
type CollectorError struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

// Integration describes an external AWS security service shown in the UI.
// In v1, GuardDuty / Security Hub / Inspector are shown as DISABLED toggles.
type Integration struct {
	Key         string `json:"key"`         // guardduty | securityhub | inspector
	Name        string `json:"name"`        // human label
	Description string `json:"description"` // what it would add
	Enabled     bool   `json:"enabled"`     // always false in v1
	Available   bool   `json:"available"`   // false => greyed-out toggle in v1
	Note        string `json:"note"`
}

// ServiceInfo describes one supported AWS service for the portal landing page.
type ServiceInfo struct {
	Key           string `json:"key"`   // ec2, s3, iam, ...
	Name          string `json:"name"`  // "Amazon EC2"
	Scope         string `json:"scope"` // "regional" | "global"
	ResourceCount int    `json:"resource_count"`
	FindingCount  int    `json:"finding_count"`
}
