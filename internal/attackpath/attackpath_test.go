package attackpath

import (
	"testing"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func baseFacts() Facts {
	return Facts{
		Account:   "111122223333",
		Instances: []Instance{{ID: "i-1", Region: "us-east-1", State: "running", PublicIP: true, SGIDs: []string{"sg-1"}, RoleARN: "role-admin"}},
		SGs:       map[string]SG{"sg-1": {Region: "us-east-1", Rules: []Rule{{From: 22, To: 22, CIDRs: []string{"0.0.0.0/0"}}}}},
		Roles: map[string]Role{
			"role-admin": {Name: "admin", IsAdmin: true},
			"role-s3":    {Name: "s3role", S3Broad: true},
		},
		Buckets: []Bucket{{Name: "b1", PublicAccessBlockFull: false, PolicyPublic: true, Encrypted: false}},
		DBs:     []DB{{ID: "db1", Public: true, Encrypted: false, SGIDs: []string{"sg-1"}, Port: 22}},
		Lambdas: []Lambda{{ARN: "lam1", URLAuthNone: true, RoleARN: "role-admin"}},
		Users:   []User{{Name: "alice", ConsoleAccess: true, MFA: false, IsAdmin: true, KeyAgesDays: []int{120}}},
	}
}

func has(paths []types.AttackPath, kind string) bool {
	for _, p := range paths {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

func TestAP1Detected(t *testing.T) {
	if !has(Compute(baseFacts(), nil, nil), "AP-1") {
		t.Fatal("AP-1 should be detected")
	}
}

func TestAP1NotWithoutPublicIP(t *testing.T) {
	f := baseFacts()
	f.Instances[0].PublicIP = false
	if has(Compute(f, nil, nil), "AP-1") {
		t.Fatal("AP-1 must not fire without a public IP")
	}
}

func TestAP1NotWithoutOpenSG(t *testing.T) {
	f := baseFacts()
	f.SGs["sg-1"] = SG{Rules: []Rule{{From: 22, To: 22, CIDRs: []string{"10.0.0.0/8"}}}}
	if has(Compute(f, nil, nil), "AP-1") {
		t.Fatal("AP-1 must not fire when SG is not world-open")
	}
}

func TestAP3PublicBucket(t *testing.T) {
	if !has(Compute(baseFacts(), nil, nil), "AP-3") {
		t.Fatal("AP-3 should be detected")
	}
	f := baseFacts()
	f.Buckets[0].Encrypted = true
	if has(Compute(f, nil, nil), "AP-3") {
		t.Fatal("AP-3 must not fire when encrypted")
	}
}

func TestAP4PublicDB(t *testing.T) {
	if !has(Compute(baseFacts(), nil, nil), "AP-4") {
		t.Fatal("AP-4 should be detected")
	}
	f := baseFacts()
	f.DBs[0].Public = false
	if has(Compute(f, nil, nil), "AP-4") {
		t.Fatal("AP-4 must not fire when not public")
	}
}

func TestAP5PublicLambda(t *testing.T) {
	if !has(Compute(baseFacts(), nil, nil), "AP-5") {
		t.Fatal("AP-5 should be detected")
	}
	f := baseFacts()
	f.Lambdas[0].URLAuthNone = false
	if has(Compute(f, nil, nil), "AP-5") {
		t.Fatal("AP-5 must not fire with auth on the URL")
	}
}

func TestAP6IdentityTakeover(t *testing.T) {
	if !has(Compute(baseFacts(), nil, nil), "AP-6") {
		t.Fatal("AP-6 should be detected")
	}
	f := baseFacts()
	f.Users[0].MFA = true
	if has(Compute(f, nil, nil), "AP-6") {
		t.Fatal("AP-6 must not fire with MFA on")
	}
}

func TestDisabledRule(t *testing.T) {
	if has(Compute(baseFacts(), nil, map[string]bool{"AP-1": false, "AP-2": true, "AP-3": true, "AP-4": true, "AP-5": true, "AP-6": true}), "AP-1") {
		t.Fatal("disabled AP-1 must not fire")
	}
}

func TestClassify(t *testing.T) {
	admin := Classify(nil, []string{"AdministratorAccess"})
	if !admin.IsAdmin {
		t.Fatal("managed AdministratorAccess => IsAdmin")
	}
	wc := Classify([]Statement{{Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}}}, nil)
	if !wc.IsAdmin || !wc.WildcardActions {
		t.Fatal("*/* => admin + wildcard")
	}
	s3 := Classify([]Statement{{Effect: "Allow", Action: []string{"s3:*"}, Resource: []string{"*"}}}, nil)
	if !s3.S3Broad {
		t.Fatal("s3:* on * => S3Broad")
	}
	deny := Classify([]Statement{{Effect: "Deny", Action: []string{"*"}, Resource: []string{"*"}}}, nil)
	if deny.IsAdmin {
		t.Fatal("Deny must not classify as admin")
	}
}
