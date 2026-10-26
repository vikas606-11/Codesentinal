package ranking

import (
	"testing"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func TestRankOrdering(t *testing.T) {
	high := types.Finding{ID: "a", Severity: types.SevCritical,
		Factors: types.RiskFactors{Severity: 1, Exposure: 1, Reachability: 1, ResourceCriticality: 0.8}}
	low := types.Finding{ID: "b", Severity: types.SevLow,
		Factors: types.RiskFactors{Severity: 0.25, Exposure: 0.3, Reachability: 0.4, ResourceCriticality: 0.5}}
	ranked := RankFindings([]types.Finding{low, high})
	if ranked[0].ID != "a" {
		t.Fatalf("expected critical first, got %s", ranked[0].ID)
	}
	if ranked[0].RiskScore <= ranked[1].RiskScore {
		t.Fatal("risk score ordering wrong")
	}
}

func TestPostureScore(t *testing.T) {
	if PostureScore(nil) != 100 {
		t.Fatal("empty should be 100")
	}
	crit := types.Finding{Severity: types.SevCritical}
	if PostureScore([]types.Finding{crit}) != 80 {
		t.Fatal("one critical should be 80")
	}
	// Per-severity cap (D13): many criticals cap the critical penalty at 60,
	// so the score floors at 40 rather than hitting 0.
	many := make([]types.Finding, 10)
	for i := range many {
		many[i] = crit
	}
	if got := PostureScore(many); got != 40 {
		t.Fatalf("critical penalty should cap at 60 -> score 40, got %d", got)
	}
	// Fixed and accepted findings do not count toward the score.
	fixedOnly := []types.Finding{{Severity: types.SevCritical, Status: types.StatusFixed}}
	if PostureScore(fixedOnly) != 100 {
		t.Fatal("fixed findings should not lower the score")
	}
}

func TestRating(t *testing.T) {
	cases := map[int]string{100: "Excellent", 80: "Good", 65: "Needs Improvement", 10: "Critical"}
	for score, want := range cases {
		if got := RatingFor(score); got != want {
			t.Fatalf("score %d: want %s got %s", score, want, got)
		}
	}
}
