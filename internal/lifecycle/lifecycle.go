// Package lifecycle reconciles the previous scan's findings with the current
// scan's so each finding keeps a stable history and an open/fixed/regressed/
// accepted status (F1, F3, F4). It is pure: no AWS, no clock except the passed-in now.
package lifecycle

import (
	"sort"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Scope limits which previous findings a scan may mark fixed. An empty Service
// and ResourceID means a full scan (whole account).
type Scope struct {
	Service    string
	ResourceID string
	Ran        map[string]bool // sources that actually completed this scan
}

// Changes lists findings that became new, fixed or regressed this scan.
type Changes struct {
	New       []types.Finding
	Fixed     []types.Finding
	Regressed []types.Finding
}

func (s Scope) inScope(f types.Finding) bool {
	if s.Service != "" && f.Service != s.Service {
		return false
	}
	if s.ResourceID != "" && f.ResourceID != s.ResourceID {
		return false
	}
	return true
}

// allSourcesRan reports whether every source that contributed to a finding ran
// in this scan. A finding whose source did not run is never marked fixed.
func allSourcesRan(f types.Finding, ran map[string]bool) bool {
	srcs := f.Sources
	if len(srcs) == 0 {
		srcs = []types.SourceRef{{Source: f.Source}}
	}
	for _, s := range srcs {
		if !ran[s.Source] {
			return false
		}
	}
	return true
}

// Reconcile merges prev and cur, applying lifecycle rules. It returns the live
// finding list (open/regressed/accepted plus recently-fixed) and the changes.
func Reconcile(prev, cur []types.Finding, sc Scope, now time.Time,
	accepted map[string]types.AcceptedRisk, retainFixed time.Duration) ([]types.Finding, Changes) {

	prevByFP := map[string]types.Finding{}
	for _, f := range prev {
		prevByFP[fp(f)] = f
	}
	curByFP := map[string]bool{}
	var out []types.Finding
	var ch Changes

	// 1) walk current findings
	for _, f := range cur {
		key := fp(f)
		curByFP[key] = true
		if p, ok := prevByFP[key]; ok {
			f.FirstSeen = p.FirstSeen
			f.LastSeen = now
			// carry plan
			if f.Plan == nil {
				f.Plan = p.Plan
			}
			if p.Status == types.StatusFixed {
				f.Status = types.StatusRegressed
				t := now
				f.RegressedAt = &t
				ch.Regressed = append(ch.Regressed, f)
			} else if p.Status == types.StatusRegressed {
				f.Status = types.StatusRegressed
				f.RegressedAt = p.RegressedAt
			} else {
				f.Status = types.StatusOpen
			}
		} else {
			f.FirstSeen = now
			f.LastSeen = now
			f.Status = types.StatusOpen
			ch.New = append(ch.New, f)
		}
		out = append(out, f)
	}

	// 2) previous findings not present now
	for _, p := range prev {
		key := fp(p)
		if curByFP[key] {
			continue
		}
		if !sc.inScope(p) {
			// outside this scan's scope -> untouched
			out = append(out, p)
			continue
		}
		if !allSourcesRan(p, sc.Ran) {
			// a contributing source didn't run -> leave as-is
			out = append(out, p)
			continue
		}
		// genuinely gone -> fixed
		if p.Status != types.StatusFixed {
			p.Status = types.StatusFixed
			t := now
			p.FixedAt = &t
			ch.Fixed = append(ch.Fixed, p)
		}
		out = append(out, p)
	}

	// 3) apply accepted-risk register
	for i := range out {
		key := fp(out[i])
		if ar, ok := accepted[key]; ok {
			if now.Before(ar.ExpiresAt) {
				out[i].Status = types.StatusAccepted
				arc := ar
				out[i].Accepted = &arc
			}
		}
	}

	// 4) drop fixed findings older than retainFixed; compute age
	var live []types.Finding
	for _, f := range out {
		if f.Status == types.StatusFixed && f.FixedAt != nil && now.Sub(*f.FixedAt) > retainFixed {
			continue
		}
		if !f.FirstSeen.IsZero() {
			f.AgeDays = int(now.Sub(f.FirstSeen).Hours() / 24)
		}
		live = append(live, f)
	}

	sort.SliceStable(live, func(i, j int) bool {
		if live[i].RiskScore != live[j].RiskScore {
			return live[i].RiskScore > live[j].RiskScore
		}
		return live[i].FirstSeen.Before(live[j].FirstSeen)
	})
	return live, ch
}

func fp(f types.Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return f.ID
}
