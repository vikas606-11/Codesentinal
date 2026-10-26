// Package dedupe merges findings that share a fingerprint so the client sees
// one finding per problem, with every source that reported it listed (F2).
package dedupe

import (
	"sort"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

var sevRank = map[types.Severity]int{
	types.SevCritical: 5, types.SevHigh: 4, types.SevMedium: 3,
	types.SevLow: 2, types.SevInformational: 1,
}

// Merge groups findings by fingerprint. For each group it keeps the highest
// severity, unions the sources, keeps the longest recommendation and the
// highest-risk factors. Returns the merged slice and how many duplicates were
// removed. Order is stable (by fingerprint).
func Merge(in []types.Finding) ([]types.Finding, int) {
	groups := map[string]*types.Finding{}
	order := []string{}
	dupes := 0

	for i := range in {
		f := in[i]
		fp := f.Fingerprint
		if fp == "" {
			fp = f.ID
		}
		ensureSource(&f)

		g, ok := groups[fp]
		if !ok {
			cp := f
			groups[fp] = &cp
			order = append(order, fp)
			continue
		}
		dupes++
		// highest severity wins (and its source becomes the primary Source)
		if sevRank[f.Severity] > sevRank[g.Severity] {
			g.Severity = f.Severity
			g.Source = f.Source
			g.Title = f.Title
			g.NativeSeverity = f.NativeSeverity
		}
		// union sources
		g.Sources = append(g.Sources, f.Sources...)
		// longest recommendation
		if len(f.Recommendation) > len(g.Recommendation) {
			g.Recommendation = f.Recommendation
		}
		// highest-risk factors (max each component)
		g.Factors = maxFactors(g.Factors, f.Factors)
		// keep a framework control if we did not have one
		if g.FrameworkControl == "" && f.FrameworkControl != "" {
			g.FrameworkControl = f.FrameworkControl
		}
	}

	out := make([]types.Finding, 0, len(order))
	for _, fp := range order {
		g := groups[fp]
		g.Sources = dedupeSources(g.Sources)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, dupes
}

func ensureSource(f *types.Finding) {
	if len(f.Sources) == 0 {
		f.Sources = []types.SourceRef{{
			Source:         f.Source,
			NativeSeverity: f.NativeSeverity,
			CheckID:        f.CheckID,
		}}
	}
}

func maxFactors(a, b types.RiskFactors) types.RiskFactors {
	max := func(x, y float64) float64 {
		if x > y {
			return x
		}
		return y
	}
	return types.RiskFactors{
		Severity:            max(a.Severity, b.Severity),
		Exposure:            max(a.Exposure, b.Exposure),
		Reachability:        max(a.Reachability, b.Reachability),
		ResourceCriticality: max(a.ResourceCriticality, b.ResourceCriticality),
	}
}

func dedupeSources(in []types.SourceRef) []types.SourceRef {
	seen := map[string]bool{}
	var out []types.SourceRef
	for _, s := range in {
		k := s.Source + "|" + s.CheckID + "|" + s.NativeID
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}
