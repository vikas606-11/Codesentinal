// Package collectors runs read-only security checks and returns normalized findings.
package collectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/sriramg-aivar/CodeSentinal./internal/fingerprint"
	"github.com/sriramg-aivar/CodeSentinal./internal/ranking"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// OwnChecks runs free, read-only AWS config checks. Nothing is modified.
type OwnChecks struct {
	cfg       aws.Config
	accountID string
	region    string   // home region (global checks)
	regions   []string // all regions to scan for regional checks

	// filter: when set, only run checks for this service and/or resource id.
	filterService  string
	filterResource string
}

func NewOwnChecks(cfg aws.Config, accountID, region string) *OwnChecks {
	return &OwnChecks{cfg: cfg, accountID: accountID, region: region, regions: []string{region}}
}

// WithRegions sets the full list of regions for regional checks.
func (o *OwnChecks) WithRegions(regions []string) *OwnChecks {
	if len(regions) > 0 {
		o.regions = regions
	}
	return o
}

// WithFilter scopes checks to a service (and optionally a specific resource id).
// Empty strings mean "no filter".
func (o *OwnChecks) WithFilter(service, resourceID string) *OwnChecks {
	o.filterService = service
	o.filterResource = resourceID
	return o
}

func (o *OwnChecks) Name() string { return "own-check" }

func (o *OwnChecks) wants(service string) bool {
	return o.filterService == "" || o.filterService == service
}

func (o *OwnChecks) mk(checkID, service, resource, region string, sev types.Severity, title, desc, rec, control string, public, reachable bool) types.Finding {
	if region == "" {
		region = o.region
	}
	normID := fingerprint.NormaliseResourceID(service, resource, region, o.accountID)
	canon := fingerprint.Canonical("own-check", checkID)
	fp := fingerprint.Of(o.accountID, service, region, normID, canon)
	return types.Finding{
		ID: fp, Fingerprint: fp, CanonicalKey: canon, CheckID: checkID,
		Source: "own-check", NativeSeverity: string(sev),
		Severity: sev, Service: service, ResourceID: normID, Region: region,
		AccountID: o.accountID, Title: title, Description: desc, Recommendation: rec,
		FrameworkControl: control, Factors: ranking.DefaultFactors(sev, service, public, reachable),
		Sources: []types.SourceRef{{Source: "own-check", CheckID: checkID, NativeSeverity: string(sev)}},
	}
}

func (o *OwnChecks) cfgForRegion(ctx context.Context, region string) aws.Config {
	c, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		cp := o.cfg.Copy()
		cp.Region = region
		return cp
	}
	return c
}

// Collect runs every check. Per-check errors become warnings, never fatal.
func (o *OwnChecks) Collect(ctx context.Context) ([]types.Finding, []string) {
	var (
		mu       sync.Mutex
		findings []types.Finding
		warns    []string
	)
	add := func(fs []types.Finding) { mu.Lock(); findings = append(findings, fs...); mu.Unlock() }
	warn := func(w string) { mu.Lock(); warns = append(warns, w); mu.Unlock() }

	// Global checks (run once).
	if o.wants("iam") {
		if fs, err := o.checkIAM(ctx, o.cfg); err != nil {
			warn(fmt.Sprintf("own-check iam: %v", err))
		} else {
			add(fs)
		}
	}
	if o.wants("s3") {
		if fs, err := o.checkS3(ctx, o.cfg); err != nil {
			warn(fmt.Sprintf("own-check s3: %v", err))
		} else {
			add(fs)
		}
	}

	// Regional checks (per region, concurrent).
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, region := range o.regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rcfg := o.cfgForRegion(ctx, region)

			type rc struct {
				svc string
				fn  func(context.Context, aws.Config, string) ([]types.Finding, error)
			}
			for _, c := range []rc{
				{"ec2", o.checkSGs},
				{"ec2", o.checkEBS},
				{"ec2", o.checkIMDSv2},
				{"eks", o.checkEKS},
				{"rds", o.checkRDS},
				{"lambda", o.checkLambda},
				{"dynamodb", o.checkDynamoDB},
				{"cloudtrail", o.checkCloudTrail},
			} {
				if !o.wants(c.svc) {
					continue
				}
				fs, err := c.fn(ctx, rcfg, region)
				if err != nil {
					warn(fmt.Sprintf("own-check %s (%s): %v", c.svc, region, err))
					continue
				}
				add(fs)
			}
		}(region)
	}
	wg.Wait()

	// If a specific resource was requested, keep only its findings.
	if o.filterResource != "" {
		var filtered []types.Finding
		for _, f := range findings {
			if f.ResourceID == o.filterResource {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	return findings, warns
}

// ---- IAM (global) ----

func (o *OwnChecks) checkIAM(ctx context.Context, cfg aws.Config) ([]types.Finding, error) {
	c := iam.NewFromConfig(cfg)
	out, err := c.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, u := range out.Users {
		name := aws.ToString(u.UserName)
		mfa, err := c.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: u.UserName})
		if err == nil && len(mfa.MFADevices) == 0 {
			fs = append(fs, o.mk("iam-user-no-mfa", "iam", aws.ToString(u.Arn), "global", types.SevHigh,
				fmt.Sprintf("IAM user '%s' has no MFA", name),
				"Console/CLI users without MFA are a common breach vector.",
				"Enable an MFA device for this user.", "CIS 1.10", false, true))
		}
		pols, err := c.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: u.UserName})
		if err == nil {
			for _, p := range pols.AttachedPolicies {
				if aws.ToString(p.PolicyName) == "AdministratorAccess" {
					fs = append(fs, o.mk("iam-user-admin-attached", "iam", aws.ToString(u.Arn), "global", types.SevMedium,
						fmt.Sprintf("IAM user '%s' has AdministratorAccess", name),
						"Direct admin on a user violates least privilege.",
						"Prefer roles and scoped policies over user-attached admin.", "CIS 1.16", false, true))
				}
			}
		}
		// Old active access keys (> 90 days).
		keys, err := c.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
		if err == nil {
			for _, k := range keys.AccessKeyMetadata {
				if string(k.Status) != "Active" || k.CreateDate == nil {
					continue
				}
				ageDays := int(time.Since(*k.CreateDate).Hours() / 24)
				if ageDays > 90 {
					fs = append(fs, o.mk("iam-old-access-key", "iam", aws.ToString(u.Arn), "global", types.SevMedium,
						fmt.Sprintf("IAM user '%s' has an access key %d days old", name, ageDays),
						"Long-lived access keys are a common credential-leak risk.",
						"Rotate the access key and remove unused keys.", "CIS 1.14", false, true))
					break
				}
			}
		}
	}
	return fs, nil
}

// ---- S3 (global listing) ----

func (o *OwnChecks) checkS3(ctx context.Context, cfg aws.Config) ([]types.Finding, error) {
	c := s3.NewFromConfig(cfg)
	out, err := c.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		arn := "arn:aws:s3:::" + name
		pab, err := c.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
		blocked := false
		if err == nil && pab.PublicAccessBlockConfiguration != nil {
			cfg := pab.PublicAccessBlockConfiguration
			blocked = aws.ToBool(cfg.BlockPublicAcls) && aws.ToBool(cfg.IgnorePublicAcls) &&
				aws.ToBool(cfg.BlockPublicPolicy) && aws.ToBool(cfg.RestrictPublicBuckets)
		}
		if !blocked {
			fs = append(fs, o.mk("s3-public-access-block", "s3", arn, "global", types.SevHigh,
				fmt.Sprintf("S3 bucket '%s' is not fully blocking public access", name),
				"Buckets without full public-access-block can be exposed.",
				"Enable all four Block Public Access settings.", "AWS FSBP S3.1", true, true))
		}
		if _, err := c.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name}); err != nil {
			fs = append(fs, o.mk("s3-default-encryption", "s3", arn, "global", types.SevMedium,
				fmt.Sprintf("S3 bucket '%s' has no default encryption", name),
				"Objects may be stored unencrypted at rest.",
				"Enable default SSE-S3 or SSE-KMS encryption.", "AWS FSBP S3.4", false, false))
		}
	}
	return fs, nil
}

// ---- EC2 security groups (regional) ----

func (o *OwnChecks) checkSGs(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, sg := range out.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, rng := range perm.IpRanges {
				if aws.ToString(rng.CidrIp) == "0.0.0.0/0" {
					from := int32(-1)
					if perm.FromPort != nil {
						from = *perm.FromPort
					}
					sev := types.SevHigh
					if from == 22 || from == 3389 {
						sev = types.SevCritical
					}
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, o.accountID, aws.ToString(sg.GroupId))
					fs = append(fs, o.mk("ec2-sg-open-world", "ec2", arn, region, sev,
						fmt.Sprintf("Security group %s allows 0.0.0.0/0 on port %d", aws.ToString(sg.GroupId), from),
						"Open-to-the-world ingress exposes the service to the internet.",
						"Restrict the CIDR to known IPs or use SSM/VPN.", "AWS FSBP EC2.2", true, true))
				}
			}
		}
	}
	return fs, nil
}

// ---- EBS volume encryption (regional) ----

func (o *OwnChecks) checkEBS(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, v := range out.Volumes {
		if !aws.ToBool(v.Encrypted) {
			id := aws.ToString(v.VolumeId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", region, o.accountID, id)
			fs = append(fs, o.mk("ebs-unencrypted", "ec2", arn, region, types.SevMedium,
				fmt.Sprintf("EBS volume %s is not encrypted", id),
				"Unencrypted EBS volumes store data at rest in the clear.",
				"Enable EBS encryption (enable account-level default encryption).", "AWS FSBP EC2.7", false, true))
		}
	}
	return fs, nil
}

// ---- EKS public endpoint (regional) ----

func (o *OwnChecks) checkEKS(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	c := eks.NewFromConfig(cfg)
	out, err := c.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, name := range out.Clusters {
		dc, err := c.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
		if err != nil || dc.Cluster == nil {
			continue
		}
		vpc := dc.Cluster.ResourcesVpcConfig
		arn := aws.ToString(dc.Cluster.Arn)
		if vpc != nil && vpc.EndpointPublicAccess {
			for _, cidr := range vpc.PublicAccessCidrs {
				if cidr == "0.0.0.0/0" {
					fs = append(fs, o.mk("eks-public-endpoint", "eks", arn, region, types.SevHigh,
						fmt.Sprintf("EKS cluster '%s' API endpoint is public to 0.0.0.0/0", name),
						"A world-reachable Kubernetes API increases attack surface.",
						"Restrict publicAccessCidrs or use private endpoint access.", "CIS EKS 5.4.2", true, true))
				}
			}
		}
	}
	return fs, nil
}

// ---- RDS public / unencrypted (regional) ----

func (o *OwnChecks) checkRDS(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	c := rds.NewFromConfig(cfg)
	out, err := c.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, i := range out.DBInstances {
		arn := aws.ToString(i.DBInstanceArn)
		name := aws.ToString(i.DBInstanceIdentifier)
		if aws.ToBool(i.PubliclyAccessible) {
			fs = append(fs, o.mk("rds-public", "rds", arn, region, types.SevHigh,
				fmt.Sprintf("RDS instance '%s' is publicly accessible", name),
				"A publicly accessible database is reachable from the internet.",
				"Set PubliclyAccessible=false and use private subnets.", "AWS FSBP RDS.2", true, true))
		}
		if !aws.ToBool(i.StorageEncrypted) {
			fs = append(fs, o.mk("rds-unencrypted", "rds", arn, region, types.SevMedium,
				fmt.Sprintf("RDS instance '%s' storage is not encrypted", name),
				"Unencrypted RDS storage exposes data at rest.",
				"Enable storage encryption (requires recreate/snapshot copy).", "AWS FSBP RDS.3", false, true))
		}
	}
	return fs, nil
}

// ---- Lambda public function URL / wildcard role (regional) ----

func (o *OwnChecks) checkLambda(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	c := lambda.NewFromConfig(cfg)
	out, err := c.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, f := range out.Functions {
		arn := aws.ToString(f.FunctionArn)
		name := aws.ToString(f.FunctionName)
		urlc, err := c.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{FunctionName: f.FunctionName})
		if err == nil && urlc != nil && string(urlc.AuthType) == "NONE" {
			fs = append(fs, o.mk("lambda-public-url", "lambda", arn, region, types.SevHigh,
				fmt.Sprintf("Lambda '%s' has a public Function URL (AuthType NONE)", name),
				"An unauthenticated Function URL is invokable by anyone.",
				"Set AuthType=AWS_IAM or remove the Function URL.", "AWS FSBP Lambda.3", true, true))
		}
	}
	return fs, nil
}

// ---- DynamoDB encryption (regional) ----

func (o *OwnChecks) checkDynamoDB(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	c := dynamodb.NewFromConfig(cfg)
	out, err := c.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, name := range out.TableNames {
		desc, err := c.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(name)})
		if err != nil || desc.Table == nil {
			continue
		}
		// SSEDescription nil / DISABLED => using AWS-owned key (not a KMS CMK).
		if desc.Table.SSEDescription == nil {
			arn := aws.ToString(desc.Table.TableArn)
			fs = append(fs, o.mk("dynamodb-encryption", "dynamodb", arn, region, types.SevLow,
				fmt.Sprintf("DynamoDB table '%s' uses default (AWS-owned) encryption", name),
				"Default encryption gives no customer-managed key control or audit.",
				"Enable a customer-managed KMS key for sensitive tables.", "AWS FSBP DynamoDB.4", false, true))
		}
	}
	return fs, nil
}

// ---- CloudTrail multi-region (regional listing, deduped by home region) ----

func (o *OwnChecks) checkCloudTrail(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	// Only evaluate once, from the home region, to avoid duplicate findings.
	if region != o.region {
		return nil, nil
	}
	c := cloudtrail.NewFromConfig(cfg)
	out, err := c.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}
	hasMultiRegion := false
	for _, t := range out.TrailList {
		if aws.ToBool(t.IsMultiRegionTrail) {
			hasMultiRegion = true
			break
		}
	}
	if !hasMultiRegion {
		arn := fmt.Sprintf("arn:aws:cloudtrail:%s:%s:trail/*", region, o.accountID)
		return []types.Finding{o.mk("cloudtrail-multiregion", "cloudtrail", arn, region, types.SevHigh,
			"No multi-region CloudTrail trail is enabled",
			"Without a multi-region trail, API activity in other regions is not logged.",
			"Create a multi-region CloudTrail trail with log file validation.", "CIS 3.1", false, true)}, nil
	}
	return nil, nil
}

// checkIMDSv2 flags EC2 instances that still allow IMDSv1 (HttpTokens != required).
// Uses DescribeInstances (already allowed), so no extra API call.
func (o *OwnChecks) checkIMDSv2(ctx context.Context, cfg aws.Config, region string) ([]types.Finding, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}
	var fs []types.Finding
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			id := aws.ToString(i.InstanceId)
			if i.MetadataOptions != nil && string(i.MetadataOptions.HttpTokens) != "required" {
				arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, o.accountID, id)
				fs = append(fs, o.mk("ec2-imdsv2", "ec2", arn, region, types.SevMedium,
					fmt.Sprintf("EC2 instance %s allows IMDSv1 (token not required)", id),
					"IMDSv1 is vulnerable to SSRF credential theft from the instance metadata service.",
					"Set MetadataOptions HttpTokens=required to enforce IMDSv2.", "AWS FSBP EC2.8", false, true))
			}
		}
	}
	return fs, nil
}
