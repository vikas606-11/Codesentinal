// Package fixes renders fix-as-code (Terraform + CLI) for common finding types
// (F7). Pure: text/template over the finding's fields. CodeSentinal. never runs these;
// each carries a "review before applying" label and a what-could-break note.
package fixes

import (
	"strings"
	"text/template"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Fix is the rendered remediation for one finding.
type Fix struct {
	Key            string `json:"key"`
	Title          string `json:"title"`
	Terraform      string `json:"terraform"`
	CLI            string `json:"cli"`
	WhatCouldBreak string `json:"what_could_break"`
	Effort         string `json:"effort"` // S | M | L
	Label          string `json:"label"`  // always "Review before applying"
}

type tmpl struct {
	title, terraform, cli, breaks, effort string
}

// data is what templates render against.
type data struct {
	ResourceID, ResourceName, Region, Account string
}

var templates = map[string]tmpl{
	"s3-public-access-block": {
		title:     "Enable S3 Block Public Access",
		terraform: `resource "aws_s3_bucket_public_access_block" "fix" {\n  bucket                  = "{{.ResourceName}}"\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`,
		cli:       `aws s3api put-public-access-block --bucket "{{.ResourceName}}" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
		breaks:    "If anything legitimately serves public objects via this bucket, it will stop. Confirm no public website/CDN origin depends on it.",
		effort:    "S",
	},
	"s3-default-encryption": {
		title:     "Enable S3 default encryption",
		terraform: `resource "aws_s3_bucket_server_side_encryption_configuration" "fix" {\n  bucket = "{{.ResourceName}}"\n  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }\n}`,
		cli:       `aws s3api put-bucket-encryption --bucket "{{.ResourceName}}" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'`,
		breaks:    "New objects are encrypted; existing objects are unchanged. No downtime expected.",
		effort:    "S",
	},
	"sg-open-world": {
		title:     "Restrict security group ingress from the internet",
		terraform: "# Replace the 0.0.0.0/0 ingress rule with your office/VPN range:\n# cidr_blocks = [\"203.0.113.0/24\"]  # instead of 0.0.0.0/0\n# Apply via your security group resource for {{.ResourceID}}.",
		cli:       `# Review current rules, then revoke the world-open rule and add a scoped one:\naws ec2 describe-security-groups --group-ids "{{.ResourceName}}" --region "{{.Region}}"\n# aws ec2 revoke-security-group-ingress --group-id "{{.ResourceName}}" --protocol tcp --port 22 --cidr 0.0.0.0/0`,
		breaks:    "Clients outside the new CIDR range will lose access. Confirm the office/VPN range before applying. Prefer SSM Session Manager over SSH.",
		effort:    "M",
	},
	"ebs-unencrypted": {
		title:     "Encrypt the EBS volume",
		terraform: "# EBS volumes cannot be encrypted in place. Snapshot, copy the snapshot with\n# encryption, and restore a new volume for {{.ResourceID}}.",
		cli:       `aws ec2 create-snapshot --volume-id "{{.ResourceName}}" --region "{{.Region}}"\n# then: aws ec2 copy-snapshot --encrypted ... and create a new volume from it`,
		breaks:    "Requires detaching the volume and a short instance stop to swap volumes. Plan a maintenance window.",
		effort:    "L",
	},
	"ebs-default-encryption": {
		title:     "Turn on account-level EBS default encryption",
		terraform: `resource "aws_ebs_encryption_by_default" "fix" { enabled = true }`,
		cli:       `aws ec2 enable-ebs-encryption-by-default --region "{{.Region}}"`,
		breaks:    "Only affects newly created volumes. Existing volumes are unchanged.",
		effort:    "S",
	},
	"rds-public": {
		title:     "Make the RDS instance private",
		terraform: "# On the aws_db_instance for {{.ResourceID}}:\n#   publicly_accessible = false",
		cli:       `aws rds modify-db-instance --db-instance-identifier "{{.ResourceName}}" --no-publicly-accessible --apply-immediately --region "{{.Region}}"`,
		breaks:    "Any client connecting over the public endpoint will lose access. Ensure consumers are inside the VPC or reachable via VPN/peering.",
		effort:    "M",
	},
	"rds-unencrypted": {
		title:     "Encrypt RDS storage",
		terraform: "# RDS storage encryption cannot be toggled in place. Take a snapshot, copy it\n# with encryption, and restore a new instance for {{.ResourceID}}.",
		cli:       `aws rds create-db-snapshot --db-instance-identifier "{{.ResourceName}}" --db-snapshot-identifier "{{.ResourceName}}-enc" --region "{{.Region}}"\n# then copy-db-snapshot --kms-key-id ... and restore-db-instance-from-db-snapshot`,
		breaks:    "Requires a snapshot/restore and a cutover with downtime. Plan a maintenance window.",
		effort:    "L",
	},
	"iam-user-no-mfa": {
		title:     "Require MFA for the IAM user",
		terraform: "# Enforce MFA with an IAM policy that denies actions unless aws:MultiFactorAuthPresent.\n# Attach an MFA device for user {{.ResourceName}} in the console or via CLI.",
		cli:       `# Create/enable a virtual MFA device and associate it:\naws iam create-virtual-mfa-device --virtual-mfa-device-name "{{.ResourceName}}-mfa" --outfile /tmp/qr.png --bootstrap-method QRCodePNG\n# aws iam enable-mfa-device --user-name "{{.ResourceName}}" --serial-number ... --authentication-code1 ... --authentication-code2 ...`,
		breaks:    "The user must enrol an MFA device. Communicate before enforcing a deny-without-MFA policy.",
		effort:    "S",
	},
	"iam-user-admin-attached": {
		title:     "Remove direct AdministratorAccess from the user",
		terraform: "# Detach AdministratorAccess from user {{.ResourceName}} and grant access via a role\n# the user assumes with MFA, or a scoped policy.",
		cli:       `aws iam detach-user-policy --user-name "{{.ResourceName}}" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`,
		breaks:    "The user loses blanket admin. Ensure a role or scoped policy covers their real needs first.",
		effort:    "M",
	},
	"iam-old-access-key": {
		title:     "Rotate the old access key",
		terraform: "# Rotate keys outside Terraform: create a new key, update consumers, then\n# deactivate and remove the old key for user {{.ResourceName}}.",
		cli:       `aws iam create-access-key --user-name "{{.ResourceName}}"\n# update consumers, then: aws iam update-access-key --user-name "{{.ResourceName}}" --access-key-id OLDKEY --status Inactive`,
		breaks:    "Anything using the old key fails once it is deactivated. Roll out the new key to all consumers first.",
		effort:    "M",
	},
	"lambda-public-url": {
		title:     "Require IAM auth on the Lambda function URL",
		terraform: "# On the aws_lambda_function_url for {{.ResourceID}}:\n#   authorization_type = \"AWS_IAM\"",
		cli:       `aws lambda update-function-url-config --function-name "{{.ResourceName}}" --auth-type AWS_IAM --region "{{.Region}}"`,
		breaks:    "Unauthenticated callers will be rejected. Ensure callers sign requests with SigV4.",
		effort:    "S",
	},
	"dynamodb-encryption": {
		title:     "Use a customer-managed KMS key for the table",
		terraform: "# On the aws_dynamodb_table for {{.ResourceID}}:\n#   server_side_encryption { enabled = true kms_key_arn = aws_kms_key.ddb.arn }",
		cli:       `aws dynamodb update-table --table-name "{{.ResourceName}}" --sse-specification Enabled=true,SSEType=KMS --region "{{.Region}}"`,
		breaks:    "Switching to a CMK adds KMS costs and a key dependency. No data loss.",
		effort:    "S",
	},
	"cloudtrail-multiregion": {
		title:     "Create a multi-region CloudTrail trail",
		terraform: `resource "aws_cloudtrail" "fix" {\n  name                          = "org-trail"\n  s3_bucket_name                = "YOUR_LOG_BUCKET"\n  is_multi_region_trail         = true\n  enable_log_file_validation    = true\n}`,
		cli:       `aws cloudtrail create-trail --name org-trail --s3-bucket-name YOUR_LOG_BUCKET --is-multi-region-trail --enable-log-file-validation --region "{{.Region}}"\naws cloudtrail start-logging --name org-trail`,
		breaks:    "Adds S3 storage cost for logs. No impact on running workloads.",
		effort:    "M",
	},
	"eks-public-endpoint": {
		title:     "Restrict the EKS API endpoint",
		terraform: "# On the aws_eks_cluster vpc_config for {{.ResourceID}}:\n#   endpoint_public_access = false  # or set public_access_cidrs to known ranges\n#   endpoint_private_access = true",
		cli:       `aws eks update-cluster-config --name "{{.ResourceName}}" --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true --region "{{.Region}}"`,
		breaks:    "kubectl access from outside the allowed CIDRs/VPC will stop. Ensure CI and operators reach the API privately.",
		effort:    "M",
	},
	"ec2-imdsv2": {
		title:     "Enforce IMDSv2 on the instance",
		terraform: "# On the aws_instance metadata_options for {{.ResourceID}}:\n#   http_tokens = \"required\"",
		cli:       `aws ec2 modify-instance-metadata-options --instance-id "{{.ResourceName}}" --http-tokens required --http-endpoint enabled --region "{{.Region}}"`,
		breaks:    "Software using IMDSv1 must be updated to use tokens. Most modern SDKs already do.",
		effort:    "S",
	},
}

// For returns the fix for a finding by its canonical key. ok is false when there
// is no template; the caller then shows the finding's own recommendation.
func For(f types.Finding) (Fix, bool) {
	t, ok := templates[f.CanonicalKey]
	if !ok {
		return Fix{}, false
	}
	d := data{
		ResourceID:   f.ResourceID,
		ResourceName: lastSegment(f.ResourceID),
		Region:       f.Region,
		Account:      f.AccountID,
	}
	return Fix{
		Key:            f.CanonicalKey,
		Title:          t.title,
		Terraform:      render(t.terraform, d),
		CLI:            render(t.cli, d),
		WhatCouldBreak: t.breaks,
		Effort:         t.effort,
		Label:          "Review before applying",
	}, true
}

// Keys lists all template keys (for tests/coverage).
func Keys() []string {
	out := make([]string, 0, len(templates))
	for k := range templates {
		out = append(out, k)
	}
	return out
}

func render(tpl string, d data) string {
	// templates use literal \n for readability; expand them first.
	tpl = strings.ReplaceAll(tpl, `\n`, "\n")
	t, err := template.New("fix").Option("missingkey=error").Parse(tpl)
	if err != nil {
		return tpl
	}
	var b strings.Builder
	if err := t.Execute(&b, d); err != nil {
		return tpl
	}
	return b.String()
}

// lastSegment extracts the resource name from an ARN or path-like id.
func lastSegment(id string) string {
	if i := strings.LastIndexAny(id, "/:"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}
