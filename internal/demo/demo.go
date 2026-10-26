// Package demo generates deterministic synthetic data for DEMO_MODE (F19).
// No AWS call is ever made; all names are obviously fictional.
package demo

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/fingerprint"
	"github.com/sriramg-aivar/CodeSentinal./internal/ranking"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

const Account = "123456789012"

var regions = []string{"us-east-1", "eu-west-1", "ap-southeast-2"}

// Review builds the current synthetic review (resources, findings, paths).
func Review() *types.PostureReview {
	rng := rand.New(rand.NewSource(42))
	resources := demoResources()
	findings := demoFindings(rng)
	findings = ranking.RankFindings(findings)
	score := ranking.PostureScore(findings)

	return &types.PostureReview{
		ReviewID:     "demo-latest",
		AccountID:    Account,
		Regions:      regions,
		Status:       "completed",
		CreatedAt:    time.Now().UTC(),
		PostureScore: score,
		Rating:       ranking.RatingFor(score),
		Summary:      summarize(findings),
		Findings:     findings,
		Resources:    resources,
		SourcesRun:   []string{"own-check", "prowler"},
		SourcesStatus: map[string]types.SourceStatus{
			"own-check": {Ran: true, At: time.Now(), Count: len(findings)},
			"prowler":   {Ran: true, At: time.Now(), Count: len(findings) / 2},
		},
		Paths:   demoPaths(),
		Changes: types.Changes{NewCount: 2, FixedCount: 3, RegressedCount: 1},
	}
}

// History builds 8 weekly points with a believable upward trend.
func History() []types.HistoryPoint {
	var out []types.HistoryPoint
	base := 38
	for i := 0; i < 8; i++ {
		score := base + i*4
		if score > 72 {
			score = 72
		}
		out = append(out, types.HistoryPoint{
			At:     time.Now().AddDate(0, 0, -7*(7-i)),
			Score:  score,
			Rating: ranking.RatingFor(score),
			Open:   20 - i,
		})
	}
	return out
}

// Risks builds three accepted-risk entries.
func Risks() []types.AcceptedRisk {
	now := time.Now()
	return []types.AcceptedRisk{
		{Fingerprint: "demo-r1", Reason: "Legacy bastion, scheduled for decommission in Q3.", Owner: "platform-team", ExpiresAt: now.AddDate(0, 2, 0), CreatedBy: "superadmin", CreatedAt: now},
		{Fingerprint: "demo-r2", Reason: "Public docs bucket is intentional and holds no sensitive data.", Owner: "marketing", ExpiresAt: now.AddDate(0, 6, 0), CreatedBy: "superadmin", CreatedAt: now},
		{Fingerprint: "demo-r3", Reason: "Vendor requires this port temporarily during migration.", Owner: "netops", ExpiresAt: now.AddDate(0, 0, 5), CreatedBy: "superadmin", CreatedAt: now},
	}
}

func demoResources() []types.Resource {
	var rs []types.Resource
	svc := func(id, s, typ, name, region string) {
		rs = append(rs, types.Resource{ID: id, Service: s, Type: typ, Name: name, Region: region, AccountID: Account})
	}
	svc("arn:aws:ec2:us-east-1:123456789012:instance/i-0web01", "ec2", "instance", "web-prod-01", "us-east-1")
	svc("arn:aws:ec2:us-east-1:123456789012:instance/i-0api02", "ec2", "instance", "api-prod-02", "us-east-1")
	svc("arn:aws:ec2:eu-west-1:123456789012:instance/i-0bastion", "ec2", "instance", "bastion", "eu-west-1")
	svc("arn:aws:s3:::example-retail-public-docs", "s3", "bucket", "example-retail-public-docs", "us-east-1")
	svc("arn:aws:s3:::example-retail-backups", "s3", "bucket", "example-retail-backups", "eu-west-1")
	svc("arn:aws:iam::123456789012:user/j.doe", "iam", "user", "j.doe", "global")
	svc("arn:aws:iam::123456789012:user/svc-deploy", "iam", "user", "svc-deploy", "global")
	svc("arn:aws:rds:us-east-1:123456789012:db:orders-db", "rds", "db-instance", "orders-db", "us-east-1")
	svc("arn:aws:lambda:ap-southeast-2:123456789012:function:image-resize", "lambda", "function", "image-resize", "ap-southeast-2")
	svc("arn:aws:eks:us-east-1:123456789012:cluster/prod", "eks", "cluster", "prod", "us-east-1")
	svc("arn:aws:cloudtrail:us-east-1:123456789012:trail/org", "cloudtrail", "trail", "org", "us-east-1")
	return rs
}

func mkFinding(checkID, svc, region, resID string, sev types.Severity, status types.Status, title, desc, rec string, public bool, ageDays int) types.Finding {
	canon := fingerprint.Canonical("own-check", checkID)
	fp := fingerprint.Of(Account, svc, region, resID, canon)
	now := time.Now()
	first := now.AddDate(0, 0, -ageDays)
	return types.Finding{
		ID: fp, Fingerprint: fp, CanonicalKey: canon, CheckID: checkID,
		Source: "own-check", Severity: sev, NativeSeverity: string(sev),
		Service: svc, ResourceID: resID, Region: region, AccountID: Account,
		Title: title, Description: desc, Recommendation: rec, Status: status,
		FirstSeen: first, LastSeen: now, AgeDays: ageDays,
		Factors: ranking.DefaultFactors(sev, svc, public, true),
		Sources: []types.SourceRef{{Source: "own-check", CheckID: checkID}},
	}
}

func demoFindings(rng *rand.Rand) []types.Finding {
	fs := []types.Finding{
		mkFinding("ec2-sg-open-world", "ec2", "us-east-1", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-web", types.SevCritical, types.StatusOpen, "Security group sg-web allows 0.0.0.0/0 on port 22", "SSH open to the internet.", "Restrict to the office CIDR.", true, 14),
		mkFinding("s3-public-access-block", "s3", "us-east-1", "arn:aws:s3:::example-retail-public-docs", types.SevHigh, types.StatusAccepted, "S3 bucket 'example-retail-public-docs' is not blocking public access", "Public bucket.", "Enable public access block.", true, 60),
		mkFinding("rds-unencrypted", "rds", "us-east-1", "arn:aws:rds:us-east-1:123456789012:db:orders-db", types.SevMedium, types.StatusOpen, "RDS instance 'orders-db' storage is not encrypted", "Unencrypted at rest.", "Snapshot-copy-restore with encryption.", false, 30),
		mkFinding("iam-user-no-mfa", "iam", "global", "arn:aws:iam::123456789012:user/j.doe", types.SevHigh, types.StatusOpen, "IAM user 'j.doe' has no MFA", "No MFA.", "Enable MFA.", false, 9),
		mkFinding("lambda-public-url", "lambda", "ap-southeast-2", "arn:aws:lambda:ap-southeast-2:123456789012:function:image-resize", types.SevHigh, types.StatusRegressed, "Lambda 'image-resize' has a public Function URL", "Unauthenticated URL.", "Require AWS_IAM auth.", true, 3),
		mkFinding("cloudtrail-multiregion", "cloudtrail", "us-east-1", "arn:aws:cloudtrail:us-east-1:123456789012:trail/org", types.SevHigh, types.StatusFixed, "No multi-region CloudTrail trail is enabled", "No trail.", "Create a multi-region trail.", false, 45),
		mkFinding("ebs-unencrypted", "ec2", "eu-west-1", "arn:aws:ec2:eu-west-1:123456789012:volume/vol-01", types.SevMedium, types.StatusOpen, "EBS volume vol-01 is not encrypted", "Unencrypted volume.", "Enable default encryption.", false, 22),
		mkFinding("dynamodb-encryption", "dynamodb", "us-east-1", "arn:aws:dynamodb:us-east-1:123456789012:table/sessions", types.SevLow, types.StatusOpen, "DynamoDB table 'sessions' uses default encryption", "AWS-owned key.", "Use a CMK.", false, 50),
		mkFinding("eks-public-endpoint", "eks", "us-east-1", "arn:aws:eks:us-east-1:123456789012:cluster/prod", types.SevHigh, types.StatusOpen, "EKS cluster 'prod' API endpoint is public to 0.0.0.0/0", "Public API.", "Restrict publicAccessCidrs.", true, 18),
	}
	// add a few prowler-sourced to show dedupe/sources
	p := mkFinding("ec2-sg-open-world", "ec2", "us-east-1", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-web", types.SevCritical, types.StatusOpen, "Security group sg-web allows 0.0.0.0/0 on port 22", "SSH open.", "Restrict.", true, 14)
	p.Sources = append(p.Sources, types.SourceRef{Source: "prowler", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"})
	fs[0] = p
	return fs
}

func demoPaths() []types.AttackPath {
	return []types.AttackPath{
		{ID: "AP-1:i-0web01", Kind: "AP-1", Title: "Internet to administrator", Severity: types.SevCritical, Score: 100,
			Steps:    []types.PathStep{{Label: "Internet", Detail: "port 22"}, {Label: "EC2 instance", ResourceID: "i-0web01", Detail: "web-prod-01"}, {Label: "Admin role", Detail: "web-admin"}},
			Evidence: []string{"security group sg-web allows 0.0.0.0/0 on port 22", "instance web-prod-01 has a public address", "its role web-admin has administrator permissions"},
			BreakAt:  0, BreakHint: "Restrict the security group to known IPs."},
		{ID: "AP-3:example-retail-public-docs", Kind: "AP-3", Title: "Public unprotected bucket", Severity: types.SevHigh, Score: 84,
			Steps:    []types.PathStep{{Label: "Internet"}, {Label: "S3 bucket", Detail: "example-retail-public-docs"}},
			Evidence: []string{"bucket is public and lacks a full public-access block", "no default encryption"},
			BreakAt:  1, BreakHint: "Enable the bucket public-access block."},
	}
}

func summarize(fs []types.Finding) types.PostureSummary {
	sum := types.PostureSummary{Total: len(fs), BySeverity: map[string]int{}, ByService: map[string]int{}, BySource: map[string]int{}}
	for _, f := range fs {
		sum.BySeverity[string(f.Severity)]++
		sum.ByService[f.Service]++
		for _, s := range f.Sources {
			sum.BySource[s.Source]++
		}
	}
	return sum
}

var _ = fmt.Sprint
