// Package ranking implements the deterministic risk rubric.
// The checks FIND problems; this package RANKS them; Bedrock only EXPLAINS them.
package ranking

import (
	"sort"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Weights for the four rubric factors (sum = 1.0).
var weights = struct{ Severity, Exposure, Reachability, Criticality float64 }{
	Severity: 0.40, Exposure: 0.25, Reachability: 0.20, Criticality: 0.15,
}

var severityFactor = map[types.Severity]float64{
	types.SevCritical: 1.0, types.SevHigh: 0.75, types.SevMedium: 0.5,
	types.SevLow: 0.25, types.SevInformational: 0.1,
}

// Services that hold data or grant power get a higher criticality baseline.
var criticalServices = map[string]float64{
	"iam": 0.9, "rds": 0.85, "dynamodb": 0.8, "s3": 0.8, "kms": 0.9,
	"secretsmanager": 0.95, "ec2": 0.6, "lambda": 0.5, "ecs": 0.5, "eks": 0.6,
}

var posturePenalty = map[types.Severity]int{
	types.SevCritical: 20, types.SevHigh: 12, types.SevMedium: 5,
	types.SevLow: 2, types.SevInformational: 0,
}

var ratingBands = []struct {
	Min  int
	Name string
}{{90, "Excellent"}, {75, "Good"}, {60, "Needs Improvement"}, {0, "Critical"}}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// ComputeRiskScore blends the four factors into a 0..100 score (default weights).
func ComputeRiskScore(f types.RiskFactors) float64 {
	return ComputeRiskScoreW(f, weights.Severity, weights.Exposure, weights.Reachability, weights.Criticality)
}

// ComputeRiskScoreW blends factors with explicit weights.
func ComputeRiskScoreW(f types.RiskFactors, wSev, wExp, wReach, wCrit float64) float64 {
	blended := wSev*f.Severity + wExp*f.Exposure + wReach*f.Reachability + wCrit*f.ResourceCriticality
	return float64(int(clamp01(blended)*1000)) / 10 // one decimal
}

// DefaultFactors builds sensible factors when a collector doesn't set them.
func DefaultFactors(sev types.Severity, service string, public, reachable bool) types.RiskFactors {
	exposure := 0.3
	if public {
		exposure = 1.0
	}
	reach := 0.4
	if reachable {
		reach = 1.0
	}
	crit, ok := criticalServices[service]
	if !ok {
		crit = 0.5
	}
	return types.RiskFactors{
		Severity:            severityFactor[sev],
		Exposure:            exposure,
		Reachability:        reach,
		ResourceCriticality: crit,
	}
}

// RankFindings fills RiskScore and returns findings sorted most-risky first.
func RankFindings(findings []types.Finding) []types.Finding {
	for i := range findings {
		findings[i].RiskScore = ComputeRiskScore(findings[i].Factors)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})
	return findings
}

// PostureScore derives the account's 0..100 posture score (default penalties).
// Only open and regressed findings count; fixed and accepted are excluded.
func PostureScore(findings []types.Finding) int {
	return PostureScoreCfg(findings, posturePenalty, defaultCaps)
}

var defaultCaps = map[types.Severity]int{
	types.SevCritical: 60, types.SevHigh: 60, types.SevMedium: 40, types.SevLow: 20, types.SevInformational: 0,
}

// PostureScoreCfg derives the score with explicit penalties and per-severity caps.
// A severity's total penalty is capped so a large account does not always hit 0.
func PostureScoreCfg(findings []types.Finding, penalty, caps map[types.Severity]int) int {
	bySev := map[types.Severity]int{}
	for _, f := range findings {
		// only open/regressed count; blank status (legacy) counts as open
		if f.Status == types.StatusFixed || f.Status == types.StatusAccepted {
			continue
		}
		bySev[f.Severity] += penalty[f.Severity]
	}
	score := 100
	for sev, total := range bySev {
		if cap, ok := caps[sev]; ok && cap > 0 && total > cap {
			total = cap
		}
		score -= total
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// RatingForBands maps a score using explicit bands.
func RatingForBands(score int, bands []struct {
	Min  int
	Name string
}) string {
	for _, b := range bands {
		if score >= b.Min {
			return b.Name
		}
	}
	return "Critical"
}

// RatingFor maps a score to a rating band.
func RatingFor(score int) string {
	for _, b := range ratingBands {
		if score >= b.Min {
			return b.Name
		}
	}
	return "Critical"
}
