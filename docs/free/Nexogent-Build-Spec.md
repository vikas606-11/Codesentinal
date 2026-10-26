# CodeSentinal. v2: Build Specification (give this file to your AI)

You are upgrading an existing product called **CodeSentinal.**, an AWS security posture agent that an MSP deploys into one managed client's AWS account. Read this whole file before writing code. It is the single source of truth for the upgrade. The scope documents are `Sow-free-build.md` (Part A below) and `Sow-paid-build.md` (Part A plus Part B).

**Work order:** do Part A phase by phase. After each phase run the verification commands in section 12 and fix everything before starting the next phase. Do Part B only when told to.

---

## 0. Ground rules (do not break these)

1. **Read-only on the client account.** No AWS write, update, delete, enable or suppress call, ever. The only AWS write allowed is to CodeSentinal.'s own DynamoDB table. Fix-as-code is **text**; the product never runs it.
2. **Pure Go backend.** No Python, no cgo, no new language runtime. Prefer the Go standard library. Add a third-party Go module only when there is no reasonable standard-library way, and say why in the commit message. The only AWS SDK service clients already in `go.mod` are the ones the code uses today; add more only where this spec asks.
3. **Detection model.** Own checks, Prowler and the other scanners **find**. Code in `internal/ranking` **ranks**. Templates (and optionally Bedrock) **write words**. Bedrock must never create a finding, change a number, or be a finding's source. **Every feature must work with Bedrock unavailable.**
4. **No vendor or customer names in the product.** Do not write the names of the supplier company, any customer, or any reference programme in code, docs, UI text, test data or comments. Use "the MSP", "the client", "the supplier".
5. **Keep it testable.** Put logic in packages that do not import the AWS SDK or Kubernetes code (`internal/lifecycle`, `internal/dedupe`, `internal/attackpath`, `internal/fixes`, `internal/report`, `internal/alerts`, `internal/risk`, `internal/settings`, `internal/session`, `internal/audit`). Put AWS calls behind small interfaces in thin adapter code. Every pure package gets table-driven tests.
6. **Additive API.** Existing endpoints and JSON field names keep working. Add fields and endpoints; do not rename or remove.
7. **No secrets in the repo, in logs, or in API responses** (password, session secret, Slack webhook). After a secret is saved, the API returns only `"set": true`.
8. **No static AWS keys in images or the cluster.** In local mode the host's AWS profile is mounted read-only into the container.
9. **Branch.** Work on a branch named `v2-msp`. Small commits, one per task. Do not push to `main`.
10. **Do not invent AWS or Prowler field names.** Where this spec says "verify", open the real code or a recorded sample and read the actual field. If you cannot verify, leave a clearly marked `TODO(verify)` and say so in your final report.

---

## 1. What exists today (v1), and the defects to fix

Repo layout (the Go module path is whatever `go.mod` says; do not change it):

```
cmd/CodeSentinal./main.go            server entry, env config, in-process scheduler
internal/types/types.go         Resource, Finding, RiskFactors, PostureReview, Explanation, ServiceInfo, Integration
internal/discovery/discovery.go multi-region inventory (ec2, lambda, rds, dynamodb, eks regional; iam, s3 global)
internal/collectors/            ownchecks.go, prowler.go, scoutsuite.go, cloudsplaining.go
internal/ranking/ranking.go     rubric: weights 0.40/0.25/0.20/0.15, posture score, rating bands
internal/bedrock/bedrock.go     explanations with offline fallback
internal/store/                 Store interface, Memory, Dynamo (pk/sk table)
internal/auth/auth.go           password gate, in-memory tokens
internal/api/server.go          HTTP API, RunReview, RunAudit, merge logic
dashboard/                      React 18 + Vite, hash router, views/*.jsx, styles.css (dark, emoji icons)
deploy/helm/CodeSentinal./           backend, frontend, prowler CronJob, PVC, ingress, serviceaccount
deploy/iam/                     read-only policy
docs/                           PRODUCT.md, SOW.md, DEPLOYMENT.md, PREREQUISITES.md
```

Verified defects (each is fixed by the feature in brackets):

| # | Defect | Where | Fix |
|---|---|---|---|
| D1 | `ID: uuid.NewString()` and `FirstSeen: time.Now()` are set on every scan in all four collectors, so findings have no identity across scans | `collectors/*.go` | F1 |
| D2 | The same problem from two sources shows twice | `api/server.go` runScan appends all sources | F2 |
| D3 | `store.List` and `/api/v1/reviews` exist, but no history is shown or reasoned about | `api`, `dashboard` | F3 |
| D4 | No report endpoint or UI exists | `api`, `dashboard` | F9 |
| D5 | `RunAudit` calls `runScan`, which calls `disc.Inventory` for the whole account even for one resource, and only re-reads Prowler files; it does not run Prowler | `api/server.go` | F15 |
| D6 | `supportedServices` lists `cloudtrail` but discovery never emits CloudTrail resources | `discovery`, `api` | F16 |
| D7 | `auth.Gate.tokens` is an in-memory map; `bearer()` also accepts `?token=` | `auth/auth.go` | F14 |
| D8 | `cors()` sets `Access-Control-Allow-Origin: *`; ingress is HTTP only | `api`, `ingress.yaml` | F14 |
| D9 | The landing page never shows the posture score, though it is computed | `dashboard` | F17 |
| D10 | Backend and Prowler pods share one RWO EBS volume, which only mounts on one node | `prowler-pvc.yaml`, cronjob | F15 |
| D11 | The scheduler in `main.go` runs in every replica | `main.go` | lease (section 8) |
| D12 | A whole review is one DynamoDB item; it will exceed 400 KB on a large account | `store/dynamo.go` | chunking (section 8) |
| D13 | Posture score subtracts a flat penalty per finding and bottoms out at 0 on any non-trivial account | `ranking` | F8 (configurable penalties, plus a per-severity cap) |

---

## 2. Target package layout (new packages marked NEW)

```
internal/types          extend (section 3)
internal/fingerprint    NEW  canonical key + fingerprint (pure)
internal/dedupe         NEW  merge findings that share a fingerprint (pure)
internal/lifecycle      NEW  reconcile previous vs current findings (pure)
internal/risk           NEW  accepted-risk register logic (pure)
internal/attackpath     NEW  facts -> attack paths (pure)
internal/fixes          NEW  fix templates (pure, text/template)
internal/report         NEW  report data + md/html/docx renderers (pure, stdlib only)
internal/alerts         NEW  Slack payloads, suppression, URL validation (pure + net/http client)
internal/settings       NEW  settings model, validation, defaults (pure)
internal/session        NEW  signed stateless tokens, login throttle (pure)
internal/audit          NEW  audit-log entry model + CSV/JSON export (pure)
internal/kube           NEW  tiny in-cluster Kubernetes client (stdlib net/http) for Jobs
internal/demo           NEW  synthetic demo data generator (pure)
internal/store          extend: KV interface, chunking, lease
internal/discovery      extend: CloudTrail, facts for attack paths, per-service inventory
internal/collectors     extend: CheckID, stable IDs, Source interface
internal/ranking        extend: configurable weights and penalties
internal/api            extend: new handlers; keep existing
dashboard               rebuild UI (section 10)
```

---

## 3. Data model changes (`internal/types`)

Add; do not remove existing fields.

```go
type Status string
const (
    StatusOpen      Status = "open"
    StatusFixed     Status = "fixed"
    StatusRegressed Status = "regressed"
    StatusAccepted  Status = "accepted"
)

type SourceRef struct {
    Source         string `json:"source"`          // own-check | prowler | scoutsuite | cloudsplaining | (paid) securityhub | guardduty | inspector | accessanalyzer
    NativeID       string `json:"native_id,omitempty"`
    NativeSeverity string `json:"native_severity,omitempty"`
    CheckID        string `json:"check_id,omitempty"`
}

// Added to Finding:
//   Fingerprint string      `json:"fingerprint"`      // stable; also copied into ID
//   CanonicalKey string     `json:"canonical_key"`    // e.g. "sg-open-world"
//   CheckID string          `json:"check_id"`         // source-specific check id
//   Sources []SourceRef     `json:"sources"`          // after dedupe; Source stays = highest-severity source
//   Status Status           `json:"status"`
//   FirstSeen, LastSeen time.Time
//   FixedAt, RegressedAt *time.Time
//   AgeDays int             `json:"age_days"`         // computed on read
//   OnPath []string         `json:"on_path,omitempty"`// attack path IDs
//   Plan *Plan              `json:"plan,omitempty"`   // owner/effort/due, joined on read
//   Accepted *AcceptedRisk  `json:"accepted,omitempty"`

type Plan struct {
    Owner string     `json:"owner"`
    Effort string    `json:"effort"` // "S" | "M" | "L" | ""
    DueDate *string  `json:"due_date"` // YYYY-MM-DD
    UpdatedAt time.Time `json:"updated_at"`
}

type AcceptedRisk struct {
    Fingerprint string    `json:"fingerprint"`
    Reason      string    `json:"reason"`      // required, 10..1000 chars
    Owner       string    `json:"owner"`       // required
    ExpiresAt   time.Time `json:"expires_at"`  // required, max 365 days ahead
    CreatedAt   time.Time `json:"created_at"`
    CreatedBy   string    `json:"created_by"`
}

type AttackPath struct {
    ID        string      `json:"id"`          // "AP-1:<instance-id>"
    Kind      string      `json:"kind"`        // AP-1..AP-6
    Title     string      `json:"title"`
    Severity  Severity    `json:"severity"`
    Score     float64     `json:"score"`
    Steps     []PathStep  `json:"steps"`       // ordered nodes with label, resource id, detail
    Evidence  []string    `json:"evidence"`    // human sentences, each backed by a fact
    BreakAt   int         `json:"break_at"`    // index in Steps of the cheapest break
    BreakHint string      `json:"break_hint"`
    FindingIDs []string   `json:"finding_ids"`
    Signals   []string    `json:"signals,omitempty"` // paid: "known-exploit CVE", "active threat"
}
type PathStep struct{ Label, ResourceID, Detail string }

type HistoryPoint struct {
    At time.Time `json:"at"`; ReviewID string `json:"review_id"`
    Score int `json:"score"`; Rating string `json:"rating"`
    Open int `json:"open"`; BySeverity map[string]int `json:"by_severity"`
    New, Fixed, Regressed, Accepted int
}
```

`PostureReview` gains: `Paths []AttackPath`, `Changes Changes` (`New`, `Fixed`, `Regressed` as finding IDs and counts), `SourcesStatus map[string]SourceStatus` (`ran bool`, `error string`, `at time.Time`, `count int`), `DuplicatesMerged int`.

**Finding ID rule:** `ID = Fingerprint`. Explanation links and UI routes use it, so they survive rescans.

---

## 4. Fingerprint and canonical keys (F1, F2)

`internal/fingerprint`:

```go
// Canonical returns the canonical key for a source check, or "<source>:<checkID>" if unmapped.
func Canonical(source, checkID string) string
// Of builds the stable fingerprint: first 16 hex chars of sha256 over
// lower(account) | service | lower(region) | resourceID | canonicalKey
func Of(account, service, region, resourceID, canonicalKey string) string
```

- Load the mapping from an embedded JSON file `internal/fingerprint/equivalence.json` (`go:embed`). Shape: `{ "own-check": {"<check-id>": "<canonical>"}, "prowler": {"<check-id>": "<canonical>"}, "securityhub": {...} }`. It must be editable without code changes. Unknown checks are **never dropped**; they get `source:checkID` as their key.
- Give every own check an explicit stable `CheckID` (for example `ec2-sg-open-world`, `s3-public-access-block`, `iam-user-no-mfa`, `iam-user-admin-attached`, `ebs-unencrypted`, `eks-public-endpoint`, `rds-public`, `rds-unencrypted`, `lambda-public-url`, `dynamodb-encryption`, `cloudtrail-multiregion`, `s3-default-encryption`; keep the ids of any other existing check stable too). The canonical key for an own check is usually the same string.
- For Prowler, **verify** which OCSF field `prowler.go` already reads for the check identifier (in Prowler OCSF output the check id is typically under `metadata.event_code`; confirm in a real sample file and in `prowler_test.go`). Map the most common Prowler check ids to the canonical keys above. To find exact ids, read the sample file or the Prowler check list for the pinned version; do not guess. Start with the equivalents of the existing own checks only.
- Resource ids must be normalised the same way across sources (ARN form). Write `NormaliseResourceID(service, id, region, account)` and test it with an instance id vs ARN, a bucket name vs ARN, an IAM user name vs ARN.
- `Of` must be pure and deterministic. Tests: same inputs give same output; changing any one input changes it; case differences in region do not.

`internal/dedupe`:

```go
// Merge groups findings by Fingerprint. For each group: keep the highest severity,
// union the Sources, keep the longest recommendation, keep the highest-risk Factors,
// and record how many were merged. Returns the merged slice and the count of duplicates removed.
func Merge(in []types.Finding) ([]types.Finding, int)
```

Tests: two sources same key -> one finding with two `Sources`; different resource -> two findings; severity precedence; stable order.

---

## 5. Lifecycle (F1, F3, F4)

`internal/lifecycle`:

```go
type Scope struct {
    Service    string          // "" = all
    ResourceID string          // "" = all in service
    Ran        map[string]bool // sources that actually completed in this scan
}
type Changes struct{ New, Fixed, Regressed []types.Finding }

func Reconcile(prev, cur []types.Finding, sc Scope, now time.Time,
               accepted map[string]types.AcceptedRisk, retainFixed time.Duration) ([]types.Finding, Changes)
```

Rules (write a test for every line):

1. Index `prev` and `cur` by fingerprint.
2. For each `cur` finding: if in `prev`, keep `FirstSeen`; set `LastSeen = now`; if `prev.Status == fixed` -> `regressed`, set `RegressedAt`, record in `Changes.Regressed`; else keep `open` (or `regressed` if it already was). If not in `prev`: `open`, `FirstSeen = LastSeen = now`, record in `Changes.New`.
3. For each `prev` finding **inside scope** (service/resource match) that is not in `cur`: if **every** `SourceRef.Source` on it has `Ran[source] == true`, mark `fixed`, set `FixedAt`, record in `Changes.Fixed`. If any contributing source did not run, **leave it untouched** (this is what stops a missing Prowler file from "fixing" everything).
4. `prev` findings outside scope are returned untouched.
5. Accepted risks: if a finding's fingerprint has an unexpired `AcceptedRisk`, set `Status = accepted`. If the entry expired, status returns to open/regressed and the finding is listed for an "expiring/expired" alert.
6. Drop `fixed` findings older than `retainFixed` (default 90 days) from the live list. History keeps the counts.
7. Output is sorted by risk score descending, then by `FirstSeen`.

`ranking.PostureScore` must count only `open` and `regressed` findings. `accepted` and `fixed` are excluded.

History: after each **full** scan, build a `HistoryPoint` and store it (section 8).

---

## 6. Scoring settings (F8)

`internal/settings` holds `Rubric{Weights{Severity, Exposure, Reachability, Criticality float64}, Penalty map[Severity]int, PerSeverityCap map[Severity]int, Bands []Band}`. Validation: each weight in [0,1], sum within 0.001 of 1; penalties 0..50; caps >= 0. Defaults equal the current constants. Change `ranking` so `ComputeRiskScore` and `PostureScore` take a `Rubric` (keep the old functions as wrappers using defaults so existing tests pass). **Per-severity cap:** a severity's total penalty is limited to its cap (defaults: Critical 60, High 60, Medium 40, Low 20) so a large account does not always show 0 (defect D13). Tests for each.

---

## 7. Intelligence

### 7.1 Attack paths (F6): `internal/attackpath`

Pure package. Input is plain data; discovery fills it (section 9).

```go
type Facts struct {
    Account string
    Instances []Instance      // ID, Region, Name, State, PublicIP bool, SGIDs []string, RoleARN string
    SGs       map[string]SG   // id -> {Region, Rules []Rule}; Rule{Proto string, From, To int, CIDRs []string}
    Roles     map[string]Role // arn -> {Name, IsAdmin bool, WildcardActions bool, S3Broad bool}
    Buckets   []Bucket        // Name, Region, PublicAccessBlockFull, PolicyPublic, ACLPublic, Encrypted bool
    DBs       []DB            // ID, Region, Public, Encrypted bool, SGIDs []string, Port int
    Lambdas   []Lambda        // ARN, Region, URLAuthNone bool, RoleARN string
    Users     []User          // Name, ConsoleAccess, MFA, IsAdmin bool, KeyAgesDays []int
}
func Compute(f Facts, findings []types.Finding, enabled map[string]bool) []types.AttackPath
```

Implement exactly these six, conservatively (a path exists only if **all** conditions hold):

| Kind | Conditions | Break at |
|---|---|---|
| AP-1 Internet to administrator | instance running with PublicIP; one of its SGs has an ingress rule from `0.0.0.0/0` or `::/0` on 22, 3389, 3306, 5432, 1433, 27017, 6379, or on all ports; its role `IsAdmin` or `WildcardActions` | the SG rule |
| AP-2 Internet to data | same exposure as AP-1; role `S3Broad` (and not already AP-1 for the same instance, else mention it in AP-1's evidence) | SG rule, then role |
| AP-3 Public unprotected bucket | `!PublicAccessBlockFull` and (`PolicyPublic` or `ACLPublic`) and `!Encrypted` | public-access block |
| AP-4 Public database | `Public` and an SG ingress from the internet on `Port` and `!Encrypted` | public access flag |
| AP-5 Public function with power | `URLAuthNone` and role `IsAdmin` or `WildcardActions` | URL auth type |
| AP-6 Identity takeover | user `ConsoleAccess` and `!MFA` and `IsAdmin` and any key age > 90 | MFA |

Rules: severity Critical for AP-1, AP-4, AP-5, AP-6; High for AP-2, AP-3. `Score` = max risk score of member findings + 10, capped at 100. Link member findings by resource id and set `Finding.OnPath`. `enabled` lets Settings switch a rule off. Every `Evidence` line must cite a fact ("security group sg-123 allows 0.0.0.0/0 on port 22"). Tests: for each kind, one fixture that triggers it and one fixture per condition removed that does not.

Role classification (in the discovery adapter, not here): `IsAdmin` if the managed policy `AdministratorAccess` is attached or any attached/inline policy has an Allow statement with `Action:"*"` and `Resource:"*"`; `WildcardActions` if an Allow statement has a service-wide wildcard such as `s3:*` or `iam:*` on `Resource:"*"`; `S3Broad` if it allows `s3:*`, `s3:Get*` or `s3:Put*` on `*`. Write the policy-document classifier as a pure function over a decoded policy and test it with five policy samples.

### 7.2 Fix-as-code (F7): `internal/fixes`

```go
type Fix struct {
    Key, Title string
    Terraform, CLI string   // text/template, rendered
    WhatCouldBreak string
    Effort string            // S | M | L
    Label string             // always "Review before applying"
}
func For(f types.Finding) (Fix, bool)   // by f.CanonicalKey; false => caller shows generic recommendation
```

Use `text/template` with `.ResourceID .ResourceName .Region .Account`. Write templates for these keys (each with a Terraform snippet, an AWS CLI command, a one-sentence "what could break", and an effort): `s3-public-access-block`, `s3-default-encryption`, `sg-open-world` (SSH/RDP/all ports; tell the user to replace the CIDR with the office range), `ebs-unencrypted` (note: existing volumes need snapshot-copy-restore), `ebs-default-encryption`, `rds-public`, `rds-unencrypted` (note: needs snapshot-copy-restore, downtime), `iam-user-no-mfa`, `iam-user-admin-attached`, `iam-old-access-key`, `lambda-public-url`, `dynamodb-encryption`, `cloudtrail-multiregion`, `eks-public-endpoint`, `ec2-imdsv2`. Escape and quote resource names; never interpolate untrusted text into a shell line without quoting. Tests: render every template with sample data; fail if the output contains `{{`, `<no value>`, or an empty command; fail if any command contains a delete/terminate/destroy verb (these are recommendations that fix, not destroy; if a fix genuinely needs one, say so in `WhatCouldBreak`).

Bedrock may be asked to rephrase `WhatCouldBreak` or add context, but the templates are the source of truth and must be shown when Bedrock is off.

### 7.3 Explanations

Keep `internal/bedrock`. Change the prompt input so it never includes the account id. Cache the explanation per fingerprint + status in the store for 7 days so rescans do not re-bill. The offline explanation must include the matching `Fix` when one exists.

---

## 8. Platform and storage

### 8.1 Store: `internal/store`

Keep `Store` (`Put`, `Latest`, `Get`, `List`, `Kind`). Add:

```go
type KV interface {
    PutItem(ctx context.Context, pk, sk string, v any) error
    GetItem(ctx context.Context, pk, sk string, out any) (bool, error)
    Query(ctx context.Context, pk, skPrefix string, limit int, newestFirst bool, out any) error
    DeleteItem(ctx context.Context, pk, sk string) error
    AcquireLease(ctx context.Context, name, owner string, ttl time.Duration) (bool, error) // conditional write
}
```

Implement for Memory and Dynamo. Partitions: `review`, `history`, `risk`, `plan`, `report`, `activity`, `settings`, `lease`, `explain`. Read the existing `dynamo.go` first and match its key style.

**Chunking (D12):** when a serialised review exceeds 300 KB, store its summary as the main item and findings/resources in `sk = "<review-id>#findings#0001"`, `#0002`, ... (each under 300 KB), and reassemble on `Get`/`Latest`. Test with a 5000-finding fixture on the memory implementation with a lowered limit.

**Lease (D11):** the scheduler calls `AcquireLease(ctx, "scheduler", hostname, interval)` before a scheduled scan and skips if false. Conditional write: item absent or `expires_at < now`.

### 8.2 Access hardening (F14): `internal/session`, `internal/auth`

- **Stateless token:** `base64url(payloadJSON) + "." + base64url(HMAC-SHA256(secret, payloadB64))`. Payload `{sub:"superadmin", iat, exp, jti}`. Verify with `hmac.Equal`; check `exp`. Secret from `SESSION_SECRET` (min 32 bytes). If auth is enabled and the secret is empty, generate a random one at start and log a warning that sessions will not survive restarts or multiple replicas. TTL from `SESSION_TTL` (default 8h).
- **Remove** the `?token=` fallback in `auth.bearer`. Downloads use `fetch` with the Authorization header and a Blob in the browser.
- **Login throttle:** 5 failures per 10 minutes per client IP (and a global ceiling of 50 per 10 minutes) -> `429` with `Retry-After`. Client IP is the left-most `X-Forwarded-For` value **only when** `TRUST_PROXY=true`, otherwise `RemoteAddr`. Constant-time password compare stays.
- **CORS:** emit no CORS headers by default (the portal is same-origin via Nginx). If `ALLOWED_ORIGIN` is set, allow exactly that origin. Local dev uses the Vite proxy.
- **Nginx headers** (`dashboard/nginx.conf`): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy` locking camera/mic/geolocation, and `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'`.
- Tests: token round-trip, tampered payload fails, expired fails, throttle counts, no CORS header by default.

### 8.3 Quick audit and deep scan (F15)

**Quick audit** (`POST /api/v1/audit?service=&resource=`, keep the route and response shape): add `discovery.InventoryService(ctx, service)` so only that service is discovered; for a resource scope discover its service and filter. Run own checks with the existing filter. **Do not read Prowler files** on a quick audit. Reconcile only the own-check source in that scope (`Ran = {own-check: true}`), so Prowler findings in scope are not marked fixed. Return the existing JSON plus `"kind":"quick"` and the changes.

**Deep scan:**

- `internal/kube`: a stdlib `net/http` client using `KUBERNETES_SERVICE_HOST`/`PORT`, the token at `/var/run/secrets/kubernetes.io/serviceaccount/token`, the CA at `.../ca.crt`, and the namespace from `.../namespace`. Methods: `GetCronJob(name)`, `CreateJobFromCronJob(name, jobName)`, `GetJob(name)`, `ListJobs(labelSelector)`. `CreateJobFromCronJob` copies `spec.jobTemplate.spec` and metadata labels, sets `ttlSecondsAfterFinished: 3600`, annotation `cronjob.kubernetes.io/instantiate: manual`, and the label `CodeSentinal./deep-scan: "true"`. Define the interface `JobRunner` and test the API handler with a fake; test the client with `httptest.NewTLSServer`.
- Endpoints: `POST /api/v1/scans/deep` -> `202 {run_id, job_name}` or `409` if a deep-scan job is already active; `GET /api/v1/scans/{id}` -> `{state: queued|running|completed|failed, started_at, finished_at, message}` derived from `Job.status` (`active`, `succeeded`, `failed`, conditions). When a poll sees `succeeded` the first time, ingest the Prowler results and run a full reconcile with `Ran[prowler]=true` (scan state is kept in the store so a restart does not lose it). If the Kubernetes client is unavailable (local mode, demo mode), return `501` with a clear message and have the UI hide the button.
- Helm: `role.yaml` (Role in the release namespace: `batch/cronjobs` `get`; `batch/jobs` `create`,`get`,`list`) and `rolebinding.yaml` to the existing service account.
- **Volume co-location (D10):** add `podAffinity` (`requiredDuringSchedulingIgnoredDuringExecution`, topologyKey `kubernetes.io/hostname`) to the Prowler CronJob pod template, selecting the backend pods by label, so the RWO volume mounts. Document that moving to EFS removes the constraint.

### 8.4 Discovery completeness (F16): `internal/discovery`

- Emit CloudTrail trails as `Service:"cloudtrail", Type:"trail"`, region = the trail's home region (note `IsMultiRegionTrail` in `Tags` or a new `Attrs map[string]string`).
- Add `Resource.Attrs map[string]string` (additive) for facts the UI needs (for example `public_ip`, `state`, `engine`).
- Emit security groups (`Type:"security-group"`), volumes (`Type:"volume"`) so the service page can filter by type. Add a `type` query parameter to `/api/v1/resources`.
- `CollectFacts(ctx, regions) (attackpath.Facts, []string)` fills the `Facts` struct using calls already allowed by the read-only policy (`ec2:Describe*`, `iam:Get*/List*`, `s3:Get*/List*`, `rds:Describe*`, `lambda:Get*/List*`). Keep every SDK call behind a small interface so the assembly logic can be tested with fakes. Cap concurrency per region and time out each call.
- Add two own checks so two fix templates have something to attach to: `iam-old-access-key` (active access key older than 90 days, from `ListAccessKeys`) and `ec2-imdsv2` (use `Instance.MetadataOptions.HttpTokens` from `DescribeInstances`, so no extra API call is needed).

### 8.5 Scheduler

Read the interval from settings (`settings.Schedule`, default `6h`, 0 disables) and fall back to `SCAN_INTERVAL`. Use the lease. After a scheduled full scan: reconcile, store the review, write the history point, evaluate alerts, write an audit entry (`actor:"scheduler"`).

---

## 9. Risk register, plan, audit log, alerts, settings

### 9.1 Accepted risks (F4): `internal/risk`

Pure functions: `Validate(AcceptedRisk, now)`, `Active(map, now)`, `Expired(map, now)`. Store in partition `risk`, sk = fingerprint. Endpoints in section 11. Reason and owner are required; expiry is required and at most 365 days ahead. Revoking removes the entry and the finding returns to open on the next reconcile (also run a cheap reconcile immediately so the UI updates).

### 9.2 Plan (F5)

Store in partition `plan`, sk = fingerprint. Validate effort in {S,M,L}, due date as `YYYY-MM-DD`, owner up to 80 chars. Join onto findings on read.

### 9.3 Audit log (F11): `internal/audit`

```go
type Entry struct{ At time.Time; Actor, Action, TargetType, Target, Detail, IP string }
```

Actions (constants): `login.success`, `login.failure`, `scan.full`, `scan.quick`, `scan.deep.start`, `scan.deep.finish`, `risk.accept`, `risk.revoke`, `risk.expire`, `plan.update`, `settings.update`, `report.create`, `report.submit`, `report.approve`, `report.reject`, `report.download`, `alert.sent`, `alert.failed`. Partition `activity`, sk = `<RFC3339Nano>#<uuid>` so it sorts by time. Never log secrets or passwords. CSV export must escape formula-injection (prefix cells starting with `= + - @` with `'`). Tests for the constants coverage and CSV escaping.

### 9.4 Alerts (F12): `internal/alerts`

- Events: new critical or high finding; regressed finding; new attack path; accepted risk expiring in 7 days or expired; scan failed; (paid) new active threat.
- Message: `{"text": "..."}` plus simple mrkdwn blocks. Never include secrets. Include portal link only when `PUBLIC_URL` is set.
- **Suppression:** remember the fingerprint + event in the store (`alert` partition, 30-day TTL). Do not resend. A **digest** mode (`immediate` or `digest`) groups events from one scan into one message.
- **URL validation:** must parse as `https`, host must equal `hooks.slack.com` (or a host in `ALERT_ALLOWED_HOSTS`), no userinfo, no private IPs. Reject otherwise at save time **and** before each send. Client timeout 5 s, max 2 attempts, body size under 40 KB.
- Tests with `httptest` server: one message per new critical; none on repeat; bad URLs rejected; digest groups.

### 9.5 Settings and branding (F13): `internal/settings`

```go
type Settings struct {
    Branding struct{ MSPName, ClientName string; LogoDataURI string } // PNG or JPEG only, max 200 KB decoded
    Sources  map[string]bool        // own-check, prowler, scoutsuite, cloudsplaining (+ paid keys)
    ScanInterval string             // "6h", "12h", "24h", "off"
    Rubric   Rubric
    Reviewer string
    Alerts   struct{ Mode string; WebhookSet bool; Events map[string]bool } // webhook value stored in a Secret-backed field, never returned
    Paths    map[string]bool        // enable/disable each AP-n
}
```

Validate every field. Logo: decode the data URI, verify magic bytes for PNG or JPEG, reject SVG (script risk), reject over 200 KB. Defaults must reproduce v1 behaviour. Store in partition `settings`, sk `current`; write an audit entry on change with a **diff of keys changed, not values** for secrets.

---

## 10. Reports (F9, F10): `internal/report`

### 10.1 Data and snapshot

`report.Build(review, history, risks, plans, paths, settings, scope) Data` is a pure function returning everything a renderer needs: cover info, score and rating, previous score, trend points, change counts, top fixes (top 10 by risk, plans joined, fix text included), paths, findings grouped by service then severity, accepted risks, CIS section, scope and method (sources run with times, regions, limits), review record. **Store the `Data` as a snapshot** in partition `report` so an approved report is immutable and renders the same later. All numbers come from `Data`; renderers do arithmetic nowhere.

Scopes: `account`, `service:<key>`, `resource:<id>`. Service and resource reports omit the trend and risk register sections that do not apply.

**CIS section:** group findings by `FrameworkControl` where it starts with a CIS prefix as emitted by Prowler (verify the exact format in a sample). Show control, pass/fail/accepted counts. If no control data exists, omit the section rather than invent it.

**Narrative:** a deterministic executive summary built from the numbers (template sentences). If Bedrock is available and the setting allows it, it may rewrite the summary paragraph, receiving only counts and finding titles, and the result is flagged "AI-assisted, reviewed by <reviewer>". Never let a model produce a number.

### 10.2 Renderers (stdlib only)

- `RenderMarkdown(Data) []byte`.
- `RenderHTML(Data) []byte`: one self-contained file, inline CSS, `@media print` with page breaks before major sections, logo as a data URI, no external requests, all text escaped with `html/template`.
- `RenderDOCX(Data) ([]byte, error)`: build a minimal WordprocessingML package with `archive/zip`: `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`, `word/styles.xml`, `word/_rels/document.xml.rels`, `docProps/core.xml`, and `word/media/logo.png|jpg` when present. Needs: title and heading styles (Heading1-3), body paragraph, a table style with borders and a header row, bullet paragraphs (use an indent and a "•" character, which avoids needing `numbering.xml`), page break, header and footer with the client name and "Page X of Y" fields, inline logo via DrawingML (`wp:inline` with `a:blip r:embed`). Escape XML (`&`, `<`, `>`, quotes) and strip characters that are invalid in XML 1.0. Set the language to `en-GB`. Mark the file's core properties title and creator (the MSP name).
- **Test the DOCX:** unzip it in the test, parse every XML part with `encoding/xml`, assert required parts exist, assert the figures in `document.xml` text equal the figures in the Markdown. In CI or locally, also open it with LibreOffice headless (`soffice --headless --convert-to pdf`) and with `python-docx` if available, as a manual step in the checklist.

### 10.3 Workflow (F10)

```go
type Status string // draft | in_review | approved | rejected
type Meta struct{ ID, Scope string; Version int; ParentID string; Status Status;
   CreatedAt time.Time; CreatedBy, Reviewer, ReviewNote string; ReviewedAt *time.Time }
```

Allowed transitions: `draft -> in_review` (submit; reviewer name required, taken from settings by default), `in_review -> approved`, `in_review -> rejected` (note required), `rejected -> new draft version` (regenerates from current data, `ParentID` set, `Version+1`). `approved` is terminal and read-only. Illegal transitions return `409`. Every transition writes an audit entry. A report can be downloaded in any state, but a non-approved download carries a "DRAFT, not reviewed" watermark line in all three formats. Table-driven test for every transition.

---

## 11. API contract (all under `/api/v1`, bearer-token protected unless stated)

Existing endpoints keep their shape: `health`*, `auth/login`*, `auth/status`*, `review`, `review/latest`, `reviews`, `services`, `regions`, `resources`, `resource`, `audit`, `explain`, `integrations` (*public). Add:

| Method and path | Purpose |
|---|---|
| `GET meta`* | `{version, store, demo, local, kube_available, auth_required}`. Public, no secrets |
| `GET overview` | score, rating, previous score, trend (last 30 history points), open counts by severity, changes since last scan (counts plus top 5 each), top 5 fixes, path count, accepted count, per-source `SourceStatus`, `duplicates_merged`, next scheduled scan |
| `GET findings` | query: `status, severity, service, source, region, q, on_path, sort (risk\|age\|seen), page, limit (max 200)`; returns `{total, items}` with plan and accepted joined |
| `GET finding?id=` | one finding with explanation (cached or offline), fix, plan, accepted, path links |
| `PUT finding/plan` | body `{id, owner, effort, due_date}` |
| `GET risks` / `POST risks` / `DELETE risks?fingerprint=` | register; POST body `{fingerprint, reason, owner, expires_at}` |
| `GET paths` | attack paths with findings joined |
| `GET history?limit=` | history points |
| `POST scans/deep` / `GET scans/{id}` | deep scan (section 8.3) |
| `GET reports` / `POST reports` | list; create `{scope, service?, resource?}` returns the draft |
| `GET reports/{id}` | meta plus a compact preview |
| `POST reports/{id}/submit` / `approve` / `reject` | transitions; body `{note?, reviewer?}` |
| `GET reports/{id}/download?format=docx\|md\|html` | file download with a safe `Content-Disposition` filename |
| `GET activity` | audit log; query `action, since, until, limit, before`; `format=csv\|json` for export |
| `GET settings` / `PUT settings` | secrets returned as `{set:true}` only |
| `GET integrations` | the three native-service toggles (free: disabled; paid: live state) |

Every handler: validate input, cap sizes (`http.MaxBytesReader` 1 MB, logo 200 KB), return `{"error": "..."}` with the right status, never leak stack traces. Add method checks. Keep handlers thin; call pure packages.

---

## 12. Frontend (F17): rebuild the portal

Use the `frontend-design` guidance if your AI has it. Do not ship the current dark-blue emoji look.

### 12.1 Information architecture (hash router, keep `#/` URLs)

`Overview` `#/` · `Findings` `#/findings` · `Attack paths` `#/paths` · `Inventory` `#/inventory` (service cards, then `#/service/<key>` and `#/resource/<id>` as today) · `Risks` `#/risks` · `Reports` `#/reports` · `Activity` `#/activity` · `Settings` `#/settings`. Old deep links `#/service/...` and `#/resource/...` must still work.

### 12.2 Design system (put the tokens in `styles.css` as CSS custom properties; no CSS framework)

- **Theme:** light by default, dark available (toggle in the top bar, remembered in `localStorage` inside try/catch, and follows `prefers-color-scheme` on first visit).
- **Type:** system font stack for the UI; a monospace stack only for IDs, ARNs and code. Base 15px, scale 12/13/15/18/24/32. Numbers use `font-variant-numeric: tabular-nums`.
- **Colour:** neutral greys for chrome; one accent for actions. **Severity is the only place with saturated colour:** critical, high, medium, low, info each need a text colour and a tinted background that pass **WCAG AA contrast (4.5:1)** in both themes. Never use colour alone to carry meaning: always pair with a text label or icon.
- **Icons:** inline SVG components in `icons.jsx` (no emoji, no icon font): overview, findings, path, inventory, shield, file, clock, settings, plus service icons for ec2, s3, iam, lambda, rds, dynamodb, eks, cloudtrail, other.
- **Layout:** left sidebar on wide screens, collapsing to a top menu under 900px; content max width 1200px; spacing scale 4/8/12/16/24/32; tables for lists (sortable headers, sticky header, row hover, keyboard focus ring), cards only for summary tiles.
- **Components:** `ScoreRing` (SVG, animates once, respects `prefers-reduced-motion`), `Sparkline`/`TrendChart` (SVG, no chart library), `SeverityBadge`, `StatusBadge` (open/fixed/regressed/accepted), `SourceChips`, `PathDiagram` (steps as connected nodes with the break point highlighted; SVG), `DataTable`, `Drawer`, `Modal` (focus trap, Escape closes), `Toast`, `EmptyState`, `Skeleton`, `ConfirmDialog`, `Banner` (info, warning, demo).
- **Dependencies:** keep React 18 and Vite only. No UI kit, no chart library, no icon package.
- **Accessibility:** semantic landmarks, one `h1` per view, labelled form controls, visible focus, full keyboard operation, `aria-live` for scan progress and toasts, tables with headers.
- **States:** every data view has loading (skeleton), empty (explains what to do next) and error (message plus retry) states.

### 12.3 Screens

- **Overview:** score ring with rating; trend chart (30 points) with the previous score; "What changed since last scan" (new, fixed, regressed counts, each opens Findings with that filter); **Fix these first** (top 5, each with severity, resource, age, effort, owner, and a "Why" link); attack path count with a link; accepted risks count; per-source status strip (ran, failed, time); buttons **Quick audit all** (full own-check scan) and **Deep scan** (hidden when unavailable) with live progress; `duplicates merged` note. Paid: **Active threats** panel (Part B).
- **Findings:** filter bar (status, severity, service, source, region, on a path, text), sortable table, row opens a **Drawer** with: title and badges, why it matters (explanation), the **Fix** (tabs Terraform and CLI with copy buttons and the "Review before applying" label plus what could break), sources list, first seen / age, plan form (owner, effort, due), **Accept risk** button (modal: reason, owner, expiry date).
- **Attack paths:** a card per path with the `PathDiagram`, evidence list, the **break here** hint, and links to the member findings.
- **Inventory:** the current service cards and service/resource pages, restyled; add a resource-type filter beside the region filter; resource page shows its findings and a **Quick audit this resource** button.
- **Risks:** register table (reason, owner, expiry with "expires in N days"), revoke button, expired items highlighted.
- **Reports:** list with status badges; **New report** (scope picker); report page with preview, status stepper, submit / approve / reject (note required on reject), and download buttons for Word, Markdown, HTML. Downloads use `fetch` with the Authorization header and a Blob.
- **Activity:** filterable log with CSV and JSON export.
- **Settings:** Branding (names, logo upload with preview), Sources (toggle each; GuardDuty / Security Hub / Inspector shown **disabled** in the free build with the reason and a cost note), Schedule, Rubric (sliders with live sum and validation), Attack paths (toggle each), Reviewer, Alerts (webhook field that never shows the stored value, event checkboxes, mode, **Send test message**).
- **Login:** clean card, shows throttle message on 429, no password hints.
- **Top bar:** MSP name or logo and client name, theme toggle, sign out. A persistent **"Demo data"** banner when `meta.demo` is true; a **warning banner** when `meta.auth_required` is false or the page is served over HTTP in non-local mode.

### 12.4 Frontend verification

`npm ci && npm run build` must pass with no warnings. Run the portal in demo mode and check every screen at 1440, 1024 and 390 px widths in both themes. Check keyboard-only navigation of one full flow (open finding, accept risk, create report, approve, download). Run an automated accessibility scan (for example `axe-core` via a Playwright script, as a dev-only tool) and fix every serious or critical issue.

---

## 13. Deployment changes (`deploy/`)

1. **Ingress** (`ingress.yaml`, `values.yaml`): add `ingress.host`, `ingress.certificateArn`, `ingress.inboundCidrs`. When `certificateArn` is set: annotate `listen-ports` for 80 and 443, `ssl-redirect: '443'`, `certificate-arn`, and a modern `ssl-policy`. When `inboundCidrs` is set: `alb.ingress.kubernetes.io/inbound-cidrs`. When neither is set, render as today and have `NOTES.txt` print a clear warning that the portal is HTTP-only.
2. **Session secret** (`auth-secret.yaml`): add `SESSION_SECRET`. Use Helm `lookup` to reuse an existing secret value on upgrade, otherwise `randAlphaNum 48`, so sessions stay valid across upgrades.
3. **Backend env:** `SESSION_SECRET`, `SESSION_TTL`, `TRUST_PROXY=true` (behind the ALB), `PUBLIC_URL`, `KUBE_NAMESPACE`, `PROWLER_CRONJOB_NAME`, `REVIEWS_TABLE`, `ALLOWED_ORIGIN` (empty), `DEMO_MODE` (false).
4. **RBAC:** `role.yaml` and `rolebinding.yaml` (section 8.3).
5. **Prowler:** pin the image tag (no `latest`); add the pod affinity; keep `runAsUser: 1000` and no command override.
6. **Replicas:** allow `backend.replicaCount > 1` (lease makes it safe). Add a `PodDisruptionBudget` only if replicas > 1.
7. **IAM policy** (`deploy/iam/CodeSentinal.-readonly-policy.json`): confirm the new calls are covered (`iam:GetRolePolicy`, `ListAttachedRolePolicies`, `GetPolicyVersion`, `ListAccessKeys`, `GetLoginProfile`, `GetAccountSummary`, `ec2:DescribeSecurityGroups`, `DescribeVolumes`, `DescribeInstances`, `rds:DescribeDBInstances`, `lambda:GetFunctionUrlConfig`, `s3:GetBucketPolicyStatus`, `GetBucketAcl`, `GetBucketPublicAccessBlock`, `cloudtrail:DescribeTrails`, `GetTrailStatus`). Add what is missing. **Do not add any write action** except on the `CodeSentinal.-reviews` table.
8. Run `helm lint deploy/helm/CodeSentinal.` and `helm template` with `ingress.certificateArn` set and unset, and compare.
9. `start.sh` and `stop.sh`: pass the new values; keep `stop.sh --purge` complete.

---

## 14. Modes

### 14.1 Local mode (F18)

Add `docker-compose.yml`: services `backend` (built from `Dockerfile`, env `AWS_PROFILE`, `AWS_REGION`, `LISTEN_ADDR=:8080`, `SUPERADMIN_PASSWORD` from `.env`, volume `~/.aws:/home/nonroot/.aws:ro`) and `frontend` (built from `dashboard/`, proxying `/api` to `backend`), plus an optional `prowler` service under a compose **profile** `scan` that runs Prowler once into a shared named volume. In local mode `kube_available` is false. Provide `.env.example` and a `docs/LOCAL.md` with the three commands. The distroless image's user and home path must match the volume mount; verify.

### 14.2 Demo mode (F19): `internal/demo`

`DEMO_MODE=true` skips AWS entirely. Generate deterministic synthetic data (seeded RNG): a fictional account id `123456789012`, 8 weeks of weekly history with a believable upward trend, about 60 resources across the eight services, about 35 findings across all statuses (including fixed, regressed and accepted), all six attack paths, three accepted risks, a plan on the top five findings, and one approved sample report. Load it into the Memory store at start. **Every API write that would call AWS returns a friendly "not available in demo mode" or works against the in-memory data.** The Settings page and report creation work against memory. The portal shows the "Demo data, not a real account" banner on every screen and in every report footer. Names in the data must be obviously fictional ("Example Retail Ltd"). Test: with `DEMO_MODE=true` and no AWS credentials, every GET endpoint returns 200 and no AWS client is constructed.

---

## 15. Documentation (F20)

Update `README.md`, `docs/PRODUCT.md`, `docs/DEPLOYMENT.md`, `docs/PREREQUISITES.md`, and replace `docs/SOW.md` with `Sow-free-build.md` (or the paid version where applicable). Add `docs/LOCAL.md`, `docs/MSP-ONBOARDING.md` (checklist: access, prerequisites, deploy, baseline scan, review, first report), `docs/RUNBOOK.md` (scan stuck, deep scan failed, Prowler file missing, DynamoDB throttling, rotate the password and session secret, scale down to stop billing), and `docs/VERIFY.md` (section 16 as a checklist). Remove any vendor or customer name. Keep `.kiro/product-context.json` accurate: update `v1_addons_status` and `pending_tasks` to describe v2.

---

## 16. Verification (run after every phase; paste results in your report)

```bash
# Go
go build ./...
go vet ./...
gofmt -l .                      # must print nothing
go test ./... -race -count=1

# Portal
cd dashboard && npm ci && npm run build && cd ..

# Helm
helm lint deploy/helm/CodeSentinal.
helm template CodeSentinal. deploy/helm/CodeSentinal. --set ingress.certificateArn=arn:aws:acm:us-east-1:123456789012:certificate/x > /tmp/with-tls.yaml
helm template CodeSentinal. deploy/helm/CodeSentinal. > /tmp/no-tls.yaml

# Demo smoke (no AWS needed)
DEMO_MODE=true SUPERADMIN_PASSWORD=demo SESSION_SECRET=$(openssl rand -hex 32) go run ./cmd/CodeSentinal. &
sleep 2
TOKEN=$(curl -s -XPOST localhost:8080/api/v1/auth/login -d '{"password":"demo"}' | jq -r .token)
for p in overview findings paths risks reports history activity settings; do
  printf "%s " $p; curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/$p
done
curl -s -o /dev/null -w "no-token %{http_code}\n" localhost:8080/api/v1/overview           # expect 401
curl -s -o /dev/null -w "query-token %{http_code}\n" "localhost:8080/api/v1/overview?token=$TOKEN"  # expect 401
```

Manual (needs a real account; do these once, in phase 7): run a full scan; confirm the CloudTrail card shows trails; run a quick audit on one resource and confirm it is fast and leaves Prowler findings alone; run a deep scan and watch it complete; fix one finding in the account, rescan, confirm it becomes **fixed**; revert it, rescan, confirm **regressed**; accept a risk and confirm the score changes; generate, review, approve and download a Word report and open it in Word or LibreOffice; confirm a Slack test message arrives; confirm two backend replicas accept the same session.

If a command cannot run in your environment (for example no network for Go modules), say so plainly, list what you could not run, and give the exact command for the human to run. **Never claim something passed that you did not run.**

---

## 17. Phases (do in order; commit per task)

| Phase | Do | Exit check |
|---|---|---|
| 0 | Create `v2-msp`. Capture a real Prowler OCSF sample and an own-check sample into `testdata/`. Make sure current tests pass | baseline green |
| 1 | `fingerprint`, `dedupe`, `lifecycle`, `risk`, `settings`, rubric, store KV + chunking + lease, CloudTrail discovery, collector `CheckID`s and stable IDs, extend `RunReview`/`RunAudit` to reconcile and write history | AC-01 to AC-09, AC-21 pass |
| 2 | `attackpath`, `CollectFacts`, `fixes`, new own checks (`iam-old-access-key`, `ec2-imdsv2`) | AC-10, AC-11 pass |
| 3 | `report` (md, html, docx), workflow, `audit`, `alerts`, branding/settings handlers | AC-12 to AC-16 pass |
| 4 | `session`, auth changes, nginx headers, Helm ingress/TLS, `kube`, quick audit, deep scan | AC-17 to AC-20 pass |
| 5 | Portal rebuild per section 12 | AC-22 pass |
| 6 | Local mode, demo mode, docs | AC-23 to AC-25 pass |
| 7 | Run the manual checks on a real account; fix; final report | all AC pass |

**Definition of done:** all acceptance criteria in the SOW for the chosen edition pass; section 16 commands are green; no write actions on client resources exist (search the code for `Create`, `Put`, `Delete`, `Update`, `Modify`, `Attach`, `Enable`, `Tag` on AWS clients and justify each: only the CodeSentinal. DynamoDB table is allowed); no vendor or customer names appear anywhere (`grep -ri` the repo).

**Final report format** (end of your work): what you built per feature id; what you could not run or verify and why; every `TODO(verify)`; the exact commands the human should run next; any deviation from this spec and the reason.

---

# PART B: Paid build (only when told to; requires Part A complete)

Scope: `Sow-paid-build.md` features P1 to P7. All readers are **read-only**, **off by default**, behind one interface, and use recorded samples for tests because the free-tier account cannot enable these services.

## B1. Common source interface

```go
// internal/collectors/source.go
type Source interface {
    Name() string                                   // "securityhub" | "guardduty" | "inspector" | "accessanalyzer"
    Collect(ctx context.Context, regions []string) ([]types.Finding, []string /*warnings*/, error)
}
```

Each reader's AWS client is behind its own small interface (`SecurityHubAPI`, `GuardDutyAPI`, `InspectorAPI`, `AnalyzerAPI`) so normalisation can be tested with fakes and with JSON samples in `testdata/native/`. **Normalisation is a pure function** from a decoded native finding to `types.Finding`. A reader that returns an error sets `SourcesStatus[source] = {ran:false, error}` so lifecycle never marks its findings fixed (AC-P8).

Page through results with a cap (default 5000 per source per region) and add a warning when the cap is hit. Time out each call. Skip a region cleanly when the service is not enabled there (the API returns an access or "not subscribed" style error; treat that as "not enabled", not a failure).

## B2. Security Hub (P1)

- Region logic: call `ListFindingAggregators`; if one exists use its aggregation region only; otherwise for each enabled region call `DescribeHub` and read only where it succeeds.
- `GetFindings` filters: `RecordState = ACTIVE`, `WorkflowStatus` in `NEW`, `NOTIFIED` (skip `SUPPRESSED`, `RESOLVED`). Page with `NextToken`, `MaxResults 100`.
- Map: `Severity.Label` -> severity; `Title`, `Description`, `Remediation.Recommendation.Text` and `.Url`; `Resources[0]` `Id`, `Type`, `Region`; `AwsAccountId`; `ProductName` into `SourceRef`; `Compliance.SecurityControlId` (for example `S3.1`) into `CheckID` as `securityhub:S3.1`.
- Service from resource type prefix: `AwsEc2*` ec2, `AwsS3*` s3, `AwsIam*` iam, `AwsLambda*` lambda, `AwsRds*` rds, `AwsDynamoDb*` dynamodb, `AwsEks*` eks, `AwsCloudTrail*` cloudtrail, anything else -> `other` (shown under an **Other services** card; add it to `supportedServices` in the UI only when it has findings).
- **Verify against current AWS documentation** before coding: AWS now has more than one Security Hub finding format. Implement the classic ASFF reader behind `SecurityHubAPI`, note the format in code comments, and leave a `TODO(verify)` for a second reader if the account uses the newer format.

## B3. GuardDuty, Inspector, Access Analyzer (P2 to P4)

- **GuardDuty:** `ListDetectors`, then `ListFindings` with a criterion excluding archived findings, then `GetFindings` in batches of 50. Severity number: 9.0 or above critical, 7.0 to 8.9 high, 4.0 to 6.9 medium, below 4.0 low (verify the bands in current docs). Keep `Type`, `Resource`, `Service.EventFirstSeen/EventLastSeen`, `Service.Count`. Also fill a `Threat` list used by the **Active threats** panel.
- **Inspector:** `ListFindings` with `findingStatus = ACTIVE`; map `severity` (untriaged -> medium); resource types for EC2 instance, ECR image and Lambda function; keep `vulnerabilityId` (CVE), package name and version, `fixedInVersion`, `exploitAvailable`, `inspectorScore`. Store CVE details in `Finding.Attrs` (add `Attrs map[string]string` to `Finding`). `exploitAvailable = YES` sets `Factors.Reachability = 1.0`.
- **Access Analyzer:** `ListAnalyzers` (account type), then `ListFindingsV2` with status ACTIVE. `isPublic` -> severity high and `Factors.Exposure = 1.0`; other external access -> medium.
- Add `SourceRef.CheckID` forms: `guardduty:<Type>`, `inspector:<CVE>`, `accessanalyzer:<ResourceType>`.

## B4. Dedupe, paths, integration page (P5 to P7)

- Extend `equivalence.json` with a `securityhub` block mapping native control ids to canonical keys. **Only map controls you can verify** against the Security Hub controls reference; leave unmapped ones as `securityhub:<id>`.
- Attack paths: pass `signals` into `attackpath.Compute` (per resource: `known_exploit_cve`, `active_threat`). If an AP-1 or AP-2 instance has either signal, add it to `Signals`, raise `Score` by 10 (cap 100), and keep Severity Critical.
- `GET integrations` returns for each of guardduty, securityhub, inspector, accessanalyzer: `{key, name, description, state: not_enabled|enabled_reading|enabled_off|permission_missing, enabled_in_settings, cost_note, enablement_guide_url?}`. State comes from read-only probes (`DescribeHub`, `ListDetectors`, `BatchGetAccountStatus`, `ListAnalyzers`) with a 10 minute cache. The toggle writes only to CodeSentinal. settings. **No code path may call an enable, create or update API of these services.**
- Cost note text: "This is a paid AWS service that the client enables. Check current AWS pricing and any free trial before enabling. CodeSentinal. only reads findings."
- New policy file `deploy/iam/CodeSentinal.-native-readers-policy.json` with exactly the actions in Appendix E of the paid SOW; Helm value `nativeReaders.enabled` attaches it only when true; document it.
- UI: Overview **Active threats** panel (type, resource, severity, first and last seen, link); resource page **Vulnerabilities** tab (CVE, package, fixed-in, exploit flag); source chips show the native product; the Settings and integrations screen shows the four states.

## B5. Part B tests and exit check

Fixtures: at least three sample findings per source (including a suppressed or archived one that must be skipped, and one on an unsupported resource type that must land in `other`). Tests: normalisation per source; a reader error never marks findings fixed; with all native sources off, output equals the free build; the same problem from own check, Prowler and Security Hub merges into one finding with three sources; signal enrichment changes path score and label. Record in the final report that **AC-P10 and the live part of AC-P7 are untested** unless the human ran them in an account with the services enabled.
