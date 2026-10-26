package dedupe

import (
	"testing"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func TestMergeSameProblemTwoSources(t *testing.T) {
	in := []types.Finding{
		{Fingerprint: "abc", Source: "own-check", Severity: types.SevHigh, CheckID: "ec2-sg-open-world", Recommendation: "short"},
		{Fingerprint: "abc", Source: "prowler", Severity: types.SevCritical, CheckID: "ec2_securitygroup...", Recommendation: "a much longer recommendation"},
	}
	out, dupes := Merge(in)
	if len(out) != 1 {
		t.Fatalf("want 1 merged, got %d", len(out))
	}
	if dupes != 1 {
		t.Fatalf("want 1 duplicate, got %d", dupes)
	}
	if out[0].Severity != types.SevCritical {
		t.Fatalf("want highest severity CRITICAL, got %s", out[0].Severity)
	}
	if len(out[0].Sources) != 2 {
		t.Fatalf("want 2 sources, got %d", len(out[0].Sources))
	}
	if out[0].Recommendation != "a much longer recommendation" {
		t.Fatal("want longest recommendation kept")
	}
}

func TestMergeDifferentResource(t *testing.T) {
	in := []types.Finding{
		{Fingerprint: "a", Source: "own-check", Severity: types.SevHigh},
		{Fingerprint: "b", Source: "prowler", Severity: types.SevHigh},
	}
	out, dupes := Merge(in)
	if len(out) != 2 || dupes != 0 {
		t.Fatalf("want 2 findings 0 dupes, got %d/%d", len(out), dupes)
	}
}
