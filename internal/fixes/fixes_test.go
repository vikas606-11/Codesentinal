package fixes

import (
	"strings"
	"testing"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func TestAllTemplatesRenderCleanly(t *testing.T) {
	destructive := []string{"terminate-instances", "delete-bucket", "delete-table", "delete-db-instance", "destroy"}
	for _, key := range Keys() {
		f := types.Finding{
			CanonicalKey: key,
			ResourceID:   "arn:aws:service:us-east-1:111122223333:thing/my-resource",
			Region:       "us-east-1",
			AccountID:    "111122223333",
		}
		fix, ok := For(f)
		if !ok {
			t.Fatalf("%s: For returned not ok", key)
		}
		if fix.Label != "Review before applying" {
			t.Errorf("%s: missing review label", key)
		}
		for _, bad := range []string{"{{", "<no value>"} {
			if strings.Contains(fix.Terraform, bad) || strings.Contains(fix.CLI, bad) {
				t.Errorf("%s: unresolved placeholder %q", key, bad)
			}
		}
		if strings.TrimSpace(fix.CLI) == "" {
			t.Errorf("%s: empty CLI", key)
		}
		if fix.WhatCouldBreak == "" {
			t.Errorf("%s: missing what-could-break", key)
		}
		// destructive verbs must only appear with an explicit caveat, not as the primary action
		for _, d := range destructive {
			if strings.Contains(strings.ToLower(fix.CLI), d) {
				t.Errorf("%s: CLI contains destructive verb %q", key, d)
			}
		}
	}
}

func TestUnknownKeyNoFix(t *testing.T) {
	if _, ok := For(types.Finding{CanonicalKey: "does-not-exist"}); ok {
		t.Fatal("unknown key should return ok=false")
	}
}

func TestResourceNameExtraction(t *testing.T) {
	f := types.Finding{CanonicalKey: "s3-public-access-block", ResourceID: "arn:aws:s3:::my-bucket"}
	fix, _ := For(f)
	if !strings.Contains(fix.CLI, "my-bucket") {
		t.Fatalf("expected bucket name in CLI: %s", fix.CLI)
	}
}
