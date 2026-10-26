package lifecycle

import (
	"testing"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func mk(fp string, sev types.Severity, status types.Status, sources ...string) types.Finding {
	var sr []types.SourceRef
	for _, s := range sources {
		sr = append(sr, types.SourceRef{Source: s})
	}
	return types.Finding{Fingerprint: fp, ID: fp, Severity: sev, Status: status,
		Service: "ec2", ResourceID: "r1", Sources: sr}
}

var full = Scope{Ran: map[string]bool{"own-check": true, "prowler": true}}

func TestNewAndStableID(t *testing.T) {
	now := time.Now()
	cur := []types.Finding{mk("a", types.SevHigh, "", "own-check")}
	out, ch := Reconcile(nil, cur, full, now, nil, 90*24*time.Hour)
	if len(out) != 1 || out[0].Status != types.StatusOpen {
		t.Fatal("want one open finding")
	}
	if len(ch.New) != 1 {
		t.Fatal("want one new")
	}
	if !out[0].FirstSeen.Equal(now) {
		t.Fatal("first seen should be now for new")
	}

	// rescan unchanged -> same id, first-seen preserved
	prev := out
	later := now.Add(time.Hour)
	out2, ch2 := Reconcile(prev, []types.Finding{mk("a", types.SevHigh, "", "own-check")}, full, later, nil, 90*24*time.Hour)
	if len(ch2.New) != 0 {
		t.Fatal("rescan unchanged should produce no new")
	}
	if !out2[0].FirstSeen.Equal(now) {
		t.Fatal("first-seen must be preserved across rescan")
	}
}

func TestFixedOnlyIfAllSourcesRan(t *testing.T) {
	now := time.Now()
	prev := []types.Finding{mk("a", types.SevHigh, types.StatusOpen, "own-check", "prowler")}
	// prowler did NOT run this scan
	sc := Scope{Ran: map[string]bool{"own-check": true}}
	out, ch := Reconcile(prev, nil, sc, now, nil, 90*24*time.Hour)
	if len(ch.Fixed) != 0 {
		t.Fatal("must not fix when a contributing source did not run")
	}
	if out[0].Status != types.StatusOpen {
		t.Fatal("status should stay open")
	}

	// now all ran -> fixed
	out2, ch2 := Reconcile(prev, nil, full, now, nil, 90*24*time.Hour)
	if len(ch2.Fixed) != 1 || out2[0].Status != types.StatusFixed {
		t.Fatal("want fixed when all sources ran")
	}
}

func TestRegressedKeepsFirstSeen(t *testing.T) {
	first := time.Now().Add(-48 * time.Hour)
	fixedAt := time.Now().Add(-time.Hour)
	prev := []types.Finding{{Fingerprint: "a", ID: "a", Service: "ec2", ResourceID: "r1",
		Severity: types.SevHigh, Status: types.StatusFixed, FirstSeen: first, FixedAt: &fixedAt,
		Sources: []types.SourceRef{{Source: "own-check"}}}}
	now := time.Now()
	out, ch := Reconcile(prev, []types.Finding{mk("a", types.SevHigh, "", "own-check")}, full, now, nil, 90*24*time.Hour)
	if len(ch.Regressed) != 1 {
		t.Fatal("want regressed")
	}
	if !out[0].FirstSeen.Equal(first) {
		t.Fatal("regressed must keep original first-seen")
	}
}

func TestScopedAuditLeavesOtherScopesUntouched(t *testing.T) {
	now := time.Now()
	prev := []types.Finding{
		mk("a", types.SevHigh, types.StatusOpen, "own-check"),
		{Fingerprint: "b", ID: "b", Service: "s3", ResourceID: "bucket", Status: types.StatusOpen,
			Severity: types.SevHigh, Sources: []types.SourceRef{{Source: "own-check"}}},
	}
	// scoped to ec2; current ec2 scan finds nothing -> a fixed, b untouched
	sc := Scope{Service: "ec2", Ran: map[string]bool{"own-check": true}}
	out, ch := Reconcile(prev, nil, sc, now, nil, 90*24*time.Hour)
	if len(ch.Fixed) != 1 {
		t.Fatal("want ec2 finding fixed")
	}
	var bStatus types.Status
	for _, f := range out {
		if f.Fingerprint == "b" {
			bStatus = f.Status
		}
	}
	if bStatus != types.StatusOpen {
		t.Fatalf("s3 finding must stay open, got %s", bStatus)
	}
}

func TestAcceptedExcludedUntilExpiry(t *testing.T) {
	now := time.Now()
	cur := []types.Finding{mk("a", types.SevHigh, "", "own-check")}
	acc := map[string]types.AcceptedRisk{"a": {Fingerprint: "a", ExpiresAt: now.Add(24 * time.Hour)}}
	out, _ := Reconcile(nil, cur, full, now, acc, 90*24*time.Hour)
	if out[0].Status != types.StatusAccepted {
		t.Fatal("should be accepted while unexpired")
	}
	// expired
	accExp := map[string]types.AcceptedRisk{"a": {Fingerprint: "a", ExpiresAt: now.Add(-time.Hour)}}
	out2, _ := Reconcile(nil, cur, full, now, accExp, 90*24*time.Hour)
	if out2[0].Status == types.StatusAccepted {
		t.Fatal("expired accepted risk should not stay accepted")
	}
}
