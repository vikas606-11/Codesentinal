package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestProwlerParseReal validates the parser against a real Prowler OCSF file
// if one is present at CodeSentinal._OCSF_TESTFILE (CI/local only). Skips otherwise.
func TestProwlerParseReal(t *testing.T) {
	src := os.Getenv("CodeSentinal._OCSF_TESTFILE")
	if src == "" {
		t.Skip("set CodeSentinal._OCSF_TESTFILE to a Prowler OCSF json to run")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prowler-ocsf.ocsf.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewProwlerCollector(dir, "338449997393", "us-east-1")
	findings, warns := c.Collect(context.Background())
	t.Logf("findings=%d warnings=%v", len(findings), warns)
	if len(findings) == 0 {
		t.Fatalf("expected FAIL findings, got 0 (warns=%v)", warns)
	}
	f := findings[0]
	if f.Source != "prowler" || f.Title == "" || f.FrameworkControl == "" {
		t.Fatalf("finding not populated: %+v", f)
	}
}
