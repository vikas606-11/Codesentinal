package api

import (
	"os"
	"strings"

	"github.com/sriramg-aivar/CodeSentinal./internal/attackpath"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func osGetenv(k string) string { return os.Getenv(k) }

// buildFactsFromReview derives a conservative attackpath.Facts view from the
// discovered resources and the current findings. It is intentionally based only
// on signals already present (findings + resource attrs) so it needs no extra
// AWS calls and is deterministic/testable. Richer fact collection via the AWS
// SDK can replace this later behind the same Facts contract.
func buildFactsFromReview(account string, resources []types.Resource, findings []types.Finding) attackpath.Facts {
	f := attackpath.Facts{
		Account: account,
		SGs:     map[string]attackpath.SG{},
		Roles:   map[string]attackpath.Role{},
	}

	// index findings by canonical key + resource for quick lookup
	has := func(canon, resourceID string) bool {
		for _, fd := range findings {
			if fd.CanonicalKey == canon && fd.ResourceID == resourceID {
				return true
			}
		}
		return false
	}
	anyKey := func(canon string) []types.Finding {
		var out []types.Finding
		for _, fd := range findings {
			if fd.CanonicalKey == canon {
				out = append(out, fd)
			}
		}
		return out
	}

	// Buckets: a bucket is risky if it has the public-access-block finding and
	// also lacks default encryption (both own checks).
	for _, r := range resources {
		if r.Service != "s3" || r.Type != "bucket" {
			continue
		}
		pub := has("s3-public-access-block", r.ID)
		enc := !has("s3-default-encryption", r.ID)
		if pub {
			f.Buckets = append(f.Buckets, attackpath.Bucket{
				Name: r.Name, Region: r.Region,
				PublicAccessBlockFull: false, PolicyPublic: true, Encrypted: enc,
			})
		}
	}

	// Databases: public if the rds-public finding exists; unencrypted if rds-unencrypted.
	for _, r := range resources {
		if r.Service != "rds" {
			continue
		}
		pub := has("rds-public", r.ID)
		enc := !has("rds-unencrypted", r.ID)
		if pub {
			f.DBs = append(f.DBs, attackpath.DB{
				ID: r.ID, Region: r.Region, Public: true, Encrypted: enc,
				SGIDs: []string{"db-sg"}, Port: 5432,
			})
			f.SGs["db-sg"] = attackpath.SG{Region: r.Region, Rules: []attackpath.Rule{{From: 5432, To: 5432, CIDRs: []string{"0.0.0.0/0"}}}}
		}
	}

	// Lambdas: public URL finding.
	for _, fd := range anyKey("lambda-public-url") {
		f.Lambdas = append(f.Lambdas, attackpath.Lambda{ARN: fd.ResourceID, Region: fd.Region, URLAuthNone: true, RoleARN: "lambda-role:" + fd.ResourceID})
		f.Roles["lambda-role:"+fd.ResourceID] = attackpath.Role{Name: "lambda-role", WildcardActions: true}
	}

	// Users: no-MFA + admin + old key signals combine into AP-6.
	userState := map[string]*attackpath.User{}
	ensureUser := func(id string) *attackpath.User {
		name := id
		if i := strings.LastIndex(id, "/"); i >= 0 {
			name = id[i+1:]
		}
		u, ok := userState[id]
		if !ok {
			u = &attackpath.User{Name: name, ConsoleAccess: true}
			userState[id] = u
		}
		return u
	}
	for _, fd := range anyKey("iam-user-no-mfa") {
		ensureUser(fd.ResourceID).MFA = false
	}
	for _, fd := range anyKey("iam-user-admin-attached") {
		ensureUser(fd.ResourceID).IsAdmin = true
	}
	for _, fd := range anyKey("iam-old-access-key") {
		ensureUser(fd.ResourceID).KeyAgesDays = append(ensureUser(fd.ResourceID).KeyAgesDays, 120)
	}
	for _, u := range userState {
		f.Users = append(f.Users, *u)
	}

	return f
}
