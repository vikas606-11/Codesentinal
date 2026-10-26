package api

import (
	"testing"

	"github.com/sriramg-aivar/CodeSentinal./internal/attackpath"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func TestBuildFactsFromReviewPublicBucket(t *testing.T) {
	resources := []types.Resource{{ID: "arn:aws:s3:::b1", Service: "s3", Type: "bucket", Name: "b1", Region: "us-east-1"}}
	findings := []types.Finding{
		{CanonicalKey: "s3-public-access-block", ResourceID: "arn:aws:s3:::b1", Service: "s3"},
	}
	f := buildFactsFromReview("111122223333", resources, findings)
	if len(f.Buckets) != 1 || f.Buckets[0].Name != "b1" {
		t.Fatalf("expected one risky bucket, got %+v", f.Buckets)
	}
	// AP-3 needs unencrypted too; here no s3-default-encryption finding => Encrypted stays true
	if f.Buckets[0].Encrypted != true {
		t.Fatal("bucket should be treated as encrypted when no encryption finding present")
	}
}

func TestBuildFactsIdentityTakeover(t *testing.T) {
	findings := []types.Finding{
		{CanonicalKey: "iam-user-no-mfa", ResourceID: "arn:aws:iam::acct:user/alice", Service: "iam"},
		{CanonicalKey: "iam-user-admin-attached", ResourceID: "arn:aws:iam::acct:user/alice", Service: "iam"},
		{CanonicalKey: "iam-old-access-key", ResourceID: "arn:aws:iam::acct:user/alice", Service: "iam"},
	}
	f := buildFactsFromReview("acct", nil, findings)
	paths := attackpath.Compute(f, findings, nil)
	found := false
	for _, p := range paths {
		if p.Kind == "AP-6" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected AP-6 identity takeover from combined IAM findings")
	}
}

func TestScopeTag(t *testing.T) {
	if scopeTag("", "") != "account" {
		t.Fatal("empty scope => account")
	}
	if scopeTag("ec2", "") != "service:ec2" {
		t.Fatal("service scope")
	}
	if scopeTag("ec2", "i-1") != "resource:i-1" {
		t.Fatal("resource scope")
	}
}
