// Package discovery inventories AWS resources (read-only), grouped by service,
// across all enabled regions. Nothing is modified.
package discovery

import (
	"context"
	"sort"
	"sync"

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

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Discoverer inventories resources for one account across regions. READ-ONLY.
type Discoverer struct {
	cfg       aws.Config
	accountID string
	region    string // the "home" region for global services / fallbacks
}

func New(cfg aws.Config, accountID, region string) *Discoverer {
	return &Discoverer{cfg: cfg, accountID: accountID, region: region}
}

// EnabledRegions returns every region enabled for the account (read-only).
// Falls back to the home region on error so discovery still works.
func (d *Discoverer) EnabledRegions(ctx context.Context) ([]string, error) {
	c := ec2.NewFromConfig(d.cfg)
	out, err := c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false), // only regions enabled for this account
	})
	if err != nil {
		return []string{d.region}, err
	}
	var regions []string
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	if len(regions) == 0 {
		regions = []string{d.region}
	}
	sort.Strings(regions)
	return regions, nil
}

// cfgForRegion clones the base config pinned to a specific region.
func (d *Discoverer) cfgForRegion(ctx context.Context, region string) aws.Config {
	c, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		// Fall back to copying the base cfg with the region overridden.
		cp := d.cfg.Copy()
		cp.Region = region
		return cp
	}
	return c
}

// Inventory lists resources across ALL enabled regions. Global services
// (IAM, S3 listing) are collected once. Per-service, per-region errors become
// warnings, never fatal.
func (d *Discoverer) Inventory(ctx context.Context) ([]types.Resource, []string) {
	regions, rerr := d.EnabledRegions(ctx)

	var (
		mu    sync.Mutex
		res   []types.Resource
		warns []string
	)
	addRes := func(rs []types.Resource) {
		mu.Lock()
		res = append(res, rs...)
		mu.Unlock()
	}
	addWarn := func(w string) {
		mu.Lock()
		warns = append(warns, w)
		mu.Unlock()
	}
	if rerr != nil {
		addWarn("regions: " + rerr.Error() + " (using home region only)")
	}

	// ---- Global services (once) ----
	if rs, err := d.iam(ctx, d.cfg); err != nil {
		addWarn("iam: " + err.Error())
	} else {
		addRes(rs)
	}
	if rs, err := d.s3(ctx, d.cfg); err != nil {
		addWarn("s3: " + err.Error())
	} else {
		addRes(rs)
	}

	// ---- Regional services (concurrent per region) ----
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6) // cap concurrency
	for _, region := range regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rcfg := d.cfgForRegion(ctx, region)
			type regFn struct {
				name string
				fn   func(context.Context, aws.Config, string) ([]types.Resource, error)
			}
			for _, f := range []regFn{
				{"ec2", d.ec2},
				{"ec2sg", d.securityGroups},
				{"ec2vol", d.volumes},
				{"lambda", d.lambda},
				{"rds", d.rds},
				{"dynamodb", d.dynamodb},
				{"eks", d.eks},
				{"cloudtrail", d.cloudtrail},
			} {
				rs, err := f.fn(ctx, rcfg, region)
				if err != nil {
					addWarn(f.name + " (" + region + "): " + err.Error())
					continue
				}
				addRes(rs)
			}
		}(region)
	}
	wg.Wait()

	return res, warns
}

// ---- Global services ----

func (d *Discoverer) iam(ctx context.Context, cfg aws.Config) ([]types.Resource, error) {
	c := iam.NewFromConfig(cfg)
	out, err := c.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, u := range out.Users {
		rs = append(rs, types.Resource{
			ID: aws.ToString(u.Arn), Service: "iam", Type: "user",
			Name: aws.ToString(u.UserName), Region: "global", AccountID: d.accountID,
		})
	}
	return rs, nil
}

func (d *Discoverer) s3(ctx context.Context, cfg aws.Config) ([]types.Resource, error) {
	c := s3.NewFromConfig(cfg)
	out, err := c.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		region := d.bucketRegion(ctx, c, name)
		rs = append(rs, types.Resource{
			ID: "arn:aws:s3:::" + name, Service: "s3", Type: "bucket",
			Name: name, Region: region, AccountID: d.accountID,
		})
	}
	return rs, nil
}

// bucketRegion resolves a bucket's region; empty LocationConstraint == us-east-1.
func (d *Discoverer) bucketRegion(ctx context.Context, c *s3.Client, bucket string) string {
	out, err := c.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "global"
	}
	region := string(out.LocationConstraint)
	if region == "" {
		return "us-east-1"
	}
	return region
}

// ---- Regional services ----

func (d *Discoverer) ec2(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			name := aws.ToString(i.InstanceId)
			tags := map[string]string{}
			for _, t := range i.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				if aws.ToString(t.Key) == "Name" {
					name = aws.ToString(t.Value)
				}
			}
			rs = append(rs, types.Resource{
				ID: aws.ToString(i.InstanceId), Service: "ec2", Type: "instance",
				Name: name, Region: region, AccountID: d.accountID, Tags: tags,
			})
		}
	}
	return rs, nil
}

func (d *Discoverer) lambda(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := lambda.NewFromConfig(cfg)
	out, err := c.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, f := range out.Functions {
		rs = append(rs, types.Resource{
			ID: aws.ToString(f.FunctionArn), Service: "lambda", Type: "function",
			Name: aws.ToString(f.FunctionName), Region: region, AccountID: d.accountID,
		})
	}
	return rs, nil
}

func (d *Discoverer) rds(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := rds.NewFromConfig(cfg)
	out, err := c.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, i := range out.DBInstances {
		rs = append(rs, types.Resource{
			ID: aws.ToString(i.DBInstanceArn), Service: "rds", Type: "db-instance",
			Name: aws.ToString(i.DBInstanceIdentifier), Region: region, AccountID: d.accountID,
		})
	}
	return rs, nil
}

func (d *Discoverer) dynamodb(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := dynamodb.NewFromConfig(cfg)
	out, err := c.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, name := range out.TableNames {
		rs = append(rs, types.Resource{
			ID: name, Service: "dynamodb", Type: "table",
			Name: name, Region: region, AccountID: d.accountID,
		})
	}
	return rs, nil
}

func (d *Discoverer) eks(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := eks.NewFromConfig(cfg)
	out, err := c.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, name := range out.Clusters {
		rs = append(rs, types.Resource{
			ID: name, Service: "eks", Type: "cluster",
			Name: name, Region: region, AccountID: d.accountID,
		})
	}
	return rs, nil
}

// cloudtrail lists trails as resources (F16). region = the trail's home region.
func (d *Discoverer) cloudtrail(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := cloudtrail.NewFromConfig(cfg)
	out, err := c.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, t := range out.TrailList {
		home := aws.ToString(t.HomeRegion)
		if home == "" {
			home = region
		}
		// Only emit a trail from its home region to avoid duplicates.
		if home != region {
			continue
		}
		rs = append(rs, types.Resource{
			ID: aws.ToString(t.TrailARN), Service: "cloudtrail", Type: "trail",
			Name: aws.ToString(t.Name), Region: home, AccountID: d.accountID,
			Attrs: map[string]string{"multi_region": boolStr(aws.ToBool(t.IsMultiRegionTrail))},
		})
	}
	return rs, nil
}

// securityGroups lists SGs as resources so the UI can filter by type (F16).
func (d *Discoverer) securityGroups(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, sg := range out.SecurityGroups {
		id := aws.ToString(sg.GroupId)
		rs = append(rs, types.Resource{
			ID:      "arn:aws:ec2:" + region + ":" + d.accountID + ":security-group/" + id,
			Service: "ec2", Type: "security-group",
			Name: aws.ToString(sg.GroupName), Region: region, AccountID: d.accountID,
		})
	}
	return rs, nil
}

// volumes lists EBS volumes as resources (F16).
func (d *Discoverer) volumes(ctx context.Context, cfg aws.Config, region string) ([]types.Resource, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}
	var rs []types.Resource
	for _, v := range out.Volumes {
		id := aws.ToString(v.VolumeId)
		rs = append(rs, types.Resource{
			ID:      "arn:aws:ec2:" + region + ":" + d.accountID + ":volume/" + id,
			Service: "ec2", Type: "volume",
			Name: id, Region: region, AccountID: d.accountID,
			Attrs: map[string]string{"encrypted": boolStr(aws.ToBool(v.Encrypted))},
		})
	}
	return rs, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// InventoryService inventories only one service across all regions (used by the
// quick-audit path so a scoped audit does not re-discover the whole account).
func (d *Discoverer) InventoryService(ctx context.Context, service string) ([]types.Resource, []string) {
	regions, rerr := d.EnabledRegions(ctx)
	var (
		mu    sync.Mutex
		res   []types.Resource
		warns []string
	)
	addRes := func(rs []types.Resource) { mu.Lock(); res = append(res, rs...); mu.Unlock() }
	addWarn := func(w string) { mu.Lock(); warns = append(warns, w); mu.Unlock() }
	if rerr != nil {
		addWarn("regions: " + rerr.Error())
	}

	switch service {
	case "iam":
		if rs, err := d.iam(ctx, d.cfg); err != nil {
			addWarn("iam: " + err.Error())
		} else {
			addRes(rs)
		}
		return res, warns
	case "s3":
		if rs, err := d.s3(ctx, d.cfg); err != nil {
			addWarn("s3: " + err.Error())
		} else {
			addRes(rs)
		}
		return res, warns
	}

	regional := map[string]func(context.Context, aws.Config, string) ([]types.Resource, error){
		"ec2":        d.ec2,
		"lambda":     d.lambda,
		"rds":        d.rds,
		"dynamodb":   d.dynamodb,
		"eks":        d.eks,
		"cloudtrail": d.cloudtrail,
	}
	fn, ok := regional[service]
	if !ok {
		return res, warns
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, region := range regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rcfg := d.cfgForRegion(ctx, region)
			if rs, err := fn(ctx, rcfg, region); err != nil {
				addWarn(service + " (" + region + "): " + err.Error())
			} else {
				addRes(rs)
			}
			// EC2 also includes SGs and volumes for completeness.
			if service == "ec2" {
				if rs, err := d.securityGroups(ctx, rcfg, region); err == nil {
					addRes(rs)
				}
				if rs, err := d.volumes(ctx, rcfg, region); err == nil {
					addRes(rs)
				}
			}
		}(region)
	}
	wg.Wait()
	return res, warns
}
