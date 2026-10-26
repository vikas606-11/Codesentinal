package risk

import (
	"testing"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func TestValidate(t *testing.T) {
	now := time.Now()
	good := types.AcceptedRisk{Fingerprint: "a", Reason: "intentional for demo", Owner: "ops", ExpiresAt: now.Add(48 * time.Hour)}
	if err := Validate(good, now); err != nil {
		t.Fatalf("good entry rejected: %v", err)
	}
	if Validate(types.AcceptedRisk{Fingerprint: "a", Reason: "x", Owner: "ops", ExpiresAt: now.Add(time.Hour)}, now) == nil {
		t.Fatal("short reason should fail")
	}
	if Validate(types.AcceptedRisk{Fingerprint: "a", Reason: "long enough reason", Owner: "ops", ExpiresAt: now.Add(-time.Hour)}, now) == nil {
		t.Fatal("past expiry should fail")
	}
	if Validate(types.AcceptedRisk{Fingerprint: "a", Reason: "long enough reason", Owner: "ops", ExpiresAt: now.Add(400 * 24 * time.Hour)}, now) == nil {
		t.Fatal("too-far expiry should fail")
	}
}

func TestActiveExpired(t *testing.T) {
	now := time.Now()
	all := map[string]types.AcceptedRisk{
		"a": {Fingerprint: "a", ExpiresAt: now.Add(time.Hour)},
		"b": {Fingerprint: "b", ExpiresAt: now.Add(-time.Hour)},
	}
	if len(Active(all, now)) != 1 {
		t.Fatal("want 1 active")
	}
	if len(Expired(all, now)) != 1 {
		t.Fatal("want 1 expired")
	}
}
