// Package attackpath derives attack paths from discovered facts (F6). Pure: it
// takes plain data and returns paths. A path exists only when ALL its conditions
// hold, so it is conservative and every evidence line cites a fact.
package attackpath

import (
	"fmt"
	"sort"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Facts is the discovered input the rules reason over.
type Facts struct {
	Account   string
	Instances []Instance
	SGs       map[string]SG
	Roles     map[string]Role
	Buckets   []Bucket
	DBs       []DB
	Lambdas   []Lambda
	Users     []User
}

type Instance struct {
	ID, Region, Name string
	State            string
	PublicIP         bool
	SGIDs            []string
	RoleARN          string
}
type Rule struct {
	Proto    string
	From, To int
	CIDRs    []string
}
type SG struct {
	Region string
	Rules  []Rule
}
type Role struct {
	Name                              string
	IsAdmin, WildcardActions, S3Broad bool
}
type Bucket struct {
	Name, Region                                              string
	PublicAccessBlockFull, PolicyPublic, ACLPublic, Encrypted bool
}
type DB struct {
	ID, Region        string
	Public, Encrypted bool
	SGIDs             []string
	Port              int
}
type Lambda struct {
	ARN, Region string
	URLAuthNone bool
	RoleARN     string
}
type User struct {
	Name                        string
	ConsoleAccess, MFA, IsAdmin bool
	KeyAgesDays                 []int
}

var remoteAccessPorts = map[int]bool{22: true, 3389: true, 3306: true, 5432: true, 1433: true, 27017: true, 6379: true}

// opensWorld reports whether an SG has an ingress rule from the internet on a
// remote-access/db port or on all ports. Returns the triggering detail.
func (sg SG) opensWorld() (bool, string) {
	for _, r := range sg.Rules {
		world := false
		for _, c := range r.CIDRs {
			if c == "0.0.0.0/0" || c == "::/0" {
				world = true
			}
		}
		if !world {
			continue
		}
		if r.From == 0 && r.To == 0 {
			return true, "all ports"
		}
		if r.From <= 0 && r.To >= 65535 {
			return true, "all ports"
		}
		for p := r.From; p <= r.To && p-r.From < 100; p++ {
			if remoteAccessPorts[p] {
				return true, fmt.Sprintf("port %d", p)
			}
		}
	}
	return false, ""
}

func (sg SG) opensPort(port int) bool {
	for _, r := range sg.Rules {
		world := false
		for _, c := range r.CIDRs {
			if c == "0.0.0.0/0" || c == "::/0" {
				world = true
			}
		}
		if world && r.From <= port && port <= r.To {
			return true
		}
	}
	return false
}

// Compute returns the attack paths present in the facts. enabled lets settings
// switch a rule (AP-1..AP-6) off. findings is used to link member findings and
// to source the base risk score.
func Compute(f Facts, findings []types.Finding, enabled map[string]bool) []types.AttackPath {
	on := func(k string) bool { return enabled == nil || enabled[k] }
	var paths []types.AttackPath

	maxRiskFor := func(resourceID string) float64 {
		var m float64
		for _, fd := range findings {
			if fd.ResourceID == resourceID && fd.RiskScore > m {
				m = fd.RiskScore
			}
		}
		return m
	}
	findIDsFor := func(resourceIDs ...string) []string {
		set := map[string]bool{}
		var ids []string
		for _, fd := range findings {
			for _, rid := range resourceIDs {
				if fd.ResourceID == rid && !set[fd.ID] {
					set[fd.ID] = true
					ids = append(ids, fd.ID)
				}
			}
		}
		return ids
	}
	score := func(base float64) float64 {
		s := base + 10
		if s > 100 {
			s = 100
		}
		return s
	}

	for _, inst := range f.Instances {
		if inst.State != "" && inst.State != "running" {
			continue
		}
		if !inst.PublicIP {
			continue
		}
		var openDetail, openSG string
		for _, sgid := range inst.SGIDs {
			if sg, ok := f.SGs[sgid]; ok {
				if w, detail := sg.opensWorld(); w {
					openDetail, openSG = detail, sgid
					break
				}
			}
		}
		if openSG == "" {
			continue
		}
		role, hasRole := f.Roles[inst.RoleARN]

		// AP-1 internet -> admin
		if on("AP-1") && hasRole && (role.IsAdmin || role.WildcardActions) {
			paths = append(paths, types.AttackPath{
				ID: "AP-1:" + inst.ID, Kind: "AP-1", Title: "Internet to administrator",
				Severity: types.SevCritical, Score: score(maxRiskFor(inst.ID)),
				Steps: []types.PathStep{
					{Label: "Internet", Detail: openDetail},
					{Label: "EC2 instance", ResourceID: inst.ID, Detail: inst.Name},
					{Label: "Admin role", ResourceID: inst.RoleARN, Detail: role.Name},
				},
				Evidence: []string{
					fmt.Sprintf("security group %s allows the internet on %s", openSG, openDetail),
					fmt.Sprintf("instance %s has a public address", inst.ID),
					fmt.Sprintf("its role %s has administrator / wildcard permissions", role.Name),
				},
				BreakAt: 0, BreakHint: "Restrict the security group to known IPs.",
				FindingIDs: findIDsFor(inst.ID, "arn:aws:ec2:"+inst.Region+":"+f.Account+":security-group/"+openSG),
			})
		}
		// AP-2 internet -> data
		if on("AP-2") && hasRole && role.S3Broad && !(role.IsAdmin || role.WildcardActions) {
			paths = append(paths, types.AttackPath{
				ID: "AP-2:" + inst.ID, Kind: "AP-2", Title: "Internet to data",
				Severity: types.SevHigh, Score: score(maxRiskFor(inst.ID)),
				Steps: []types.PathStep{
					{Label: "Internet", Detail: openDetail},
					{Label: "EC2 instance", ResourceID: inst.ID, Detail: inst.Name},
					{Label: "S3-broad role", ResourceID: inst.RoleARN, Detail: role.Name},
				},
				Evidence: []string{
					fmt.Sprintf("security group %s allows the internet on %s", openSG, openDetail),
					fmt.Sprintf("instance %s has a public address", inst.ID),
					fmt.Sprintf("its role %s can read/write S3 broadly", role.Name),
				},
				BreakAt: 0, BreakHint: "Restrict the security group, then narrow the role.",
				FindingIDs: findIDsFor(inst.ID),
			})
		}
	}

	// AP-3 public unprotected bucket
	if on("AP-3") {
		for _, b := range f.Buckets {
			if !b.PublicAccessBlockFull && (b.PolicyPublic || b.ACLPublic) && !b.Encrypted {
				arn := "arn:aws:s3:::" + b.Name
				paths = append(paths, types.AttackPath{
					ID: "AP-3:" + b.Name, Kind: "AP-3", Title: "Public unprotected bucket",
					Severity: types.SevHigh, Score: score(maxRiskFor(arn)),
					Steps: []types.PathStep{
						{Label: "Internet"},
						{Label: "S3 bucket", ResourceID: arn, Detail: b.Name},
					},
					Evidence: []string{
						fmt.Sprintf("bucket %s is public and lacks a full public-access block", b.Name),
						"the bucket has no default encryption",
					},
					BreakAt: 1, BreakHint: "Enable the bucket public-access block.",
					FindingIDs: findIDsFor(arn),
				})
			}
		}
	}

	// AP-4 public database
	if on("AP-4") {
		for _, db := range f.DBs {
			if !db.Public || db.Encrypted {
				// condition: public AND exposed SG AND unencrypted
			}
			exposed := false
			for _, sgid := range db.SGIDs {
				if sg, ok := f.SGs[sgid]; ok && sg.opensPort(db.Port) {
					exposed = true
				}
			}
			if db.Public && exposed && !db.Encrypted {
				paths = append(paths, types.AttackPath{
					ID: "AP-4:" + db.ID, Kind: "AP-4", Title: "Public database",
					Severity: types.SevCritical, Score: score(maxRiskFor(db.ID)),
					Steps: []types.PathStep{
						{Label: "Internet", Detail: fmt.Sprintf("port %d", db.Port)},
						{Label: "Database", ResourceID: db.ID},
					},
					Evidence: []string{
						fmt.Sprintf("database %s is publicly accessible", db.ID),
						fmt.Sprintf("a security group allows the internet on port %d", db.Port),
						"storage is not encrypted",
					},
					BreakAt: 1, BreakHint: "Turn off public accessibility.",
					FindingIDs: findIDsFor(db.ID),
				})
			}
		}
	}

	// AP-5 public function with power
	if on("AP-5") {
		for _, l := range f.Lambdas {
			role, ok := f.Roles[l.RoleARN]
			if l.URLAuthNone && ok && (role.IsAdmin || role.WildcardActions) {
				paths = append(paths, types.AttackPath{
					ID: "AP-5:" + l.ARN, Kind: "AP-5", Title: "Public function with power",
					Severity: types.SevCritical, Score: score(maxRiskFor(l.ARN)),
					Steps: []types.PathStep{
						{Label: "Internet", Detail: "unauthenticated URL"},
						{Label: "Lambda", ResourceID: l.ARN},
						{Label: "Admin role", ResourceID: l.RoleARN, Detail: role.Name},
					},
					Evidence: []string{
						"the function URL has no authentication (AuthType NONE)",
						fmt.Sprintf("its role %s has administrator / wildcard permissions", role.Name),
					},
					BreakAt: 0, BreakHint: "Require IAM auth on the function URL.",
					FindingIDs: findIDsFor(l.ARN),
				})
			}
		}
	}

	// AP-6 identity takeover
	if on("AP-6") {
		for _, u := range f.Users {
			oldKey := false
			for _, age := range u.KeyAgesDays {
				if age > 90 {
					oldKey = true
				}
			}
			if u.ConsoleAccess && !u.MFA && u.IsAdmin && oldKey {
				arn := "arn:aws:iam::" + f.Account + ":user/" + u.Name
				paths = append(paths, types.AttackPath{
					ID: "AP-6:" + u.Name, Kind: "AP-6", Title: "Identity takeover",
					Severity: types.SevCritical, Score: score(maxRiskFor(arn)),
					Steps: []types.PathStep{
						{Label: "Credential", Detail: "no MFA, old key"},
						{Label: "IAM user", ResourceID: arn, Detail: u.Name},
						{Label: "Admin"},
					},
					Evidence: []string{
						fmt.Sprintf("user %s has console access without MFA", u.Name),
						"the user has administrator access",
						"an access key is older than 90 days",
					},
					BreakAt: 0, BreakHint: "Enforce MFA for this user.",
					FindingIDs: findIDsFor(arn),
				})
			}
		}
	}

	sort.SliceStable(paths, func(i, j int) bool { return paths[i].Score > paths[j].Score })
	return paths
}
