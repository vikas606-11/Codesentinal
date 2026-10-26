// Package api runs posture reviews and serves the HTTP API for the v2 portal.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"

	"github.com/sriramg-aivar/CodeSentinal./internal/alerts"
	"github.com/sriramg-aivar/CodeSentinal./internal/attackpath"
	"github.com/sriramg-aivar/CodeSentinal./internal/audit"
	"github.com/sriramg-aivar/CodeSentinal./internal/bedrock"
	"github.com/sriramg-aivar/CodeSentinal./internal/collectors"
	"github.com/sriramg-aivar/CodeSentinal./internal/dedupe"
	"github.com/sriramg-aivar/CodeSentinal./internal/discovery"
	"github.com/sriramg-aivar/CodeSentinal./internal/kube"
	"github.com/sriramg-aivar/CodeSentinal./internal/lifecycle"
	"github.com/sriramg-aivar/CodeSentinal./internal/ranking"
	"github.com/sriramg-aivar/CodeSentinal./internal/risk"
	"github.com/sriramg-aivar/CodeSentinal./internal/session"
	"github.com/sriramg-aivar/CodeSentinal./internal/settings"
	"github.com/sriramg-aivar/CodeSentinal./internal/store"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

var supportedServices = []types.ServiceInfo{
	{Key: "ec2", Name: "Amazon EC2", Scope: "regional"},
	{Key: "s3", Name: "Amazon S3", Scope: "global"},
	{Key: "iam", Name: "AWS IAM", Scope: "global"},
	{Key: "lambda", Name: "AWS Lambda", Scope: "regional"},
	{Key: "rds", Name: "Amazon RDS", Scope: "regional"},
	{Key: "dynamodb", Name: "Amazon DynamoDB", Scope: "regional"},
	{Key: "eks", Name: "Amazon EKS", Scope: "regional"},
	{Key: "cloudtrail", Name: "AWS CloudTrail", Scope: "regional"},
}

// Config holds server dependencies.
type Config struct {
	AWS            aws.Config
	Region         string
	BedrockModel   string
	ProwlerResults string
	ScoutResults   string
	CSPResults     string
	Store          store.Store
	Sessions       *session.Manager
	Throttle       *session.Throttle
	Password       string
	AuthEnabled    bool
	TrustProxy     bool
	PublicURL      string
	Kube           kube.JobRunner
	ProwlerCronJob string
	Demo           bool
	Local          bool
	Version        string
}

// Server is the HTTP API.
type Server struct {
	cfg       Config
	explainer *bedrock.Explainer
	st        *state
	store     store.Store

	mu            sync.RWMutex
	cachedRegions []string
	regionsAt     time.Time
	deepScans     map[string]string // run_id -> job name
	scanning      bool
}

func New(cfg Config) *Server {
	return &Server{
		cfg:       cfg,
		explainer: bedrock.New(cfg.AWS, cfg.BedrockModel),
		st:        newState(cfg.Store),
		store:     cfg.Store,
		deepScans: map[string]string{},
	}
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) accountID(ctx context.Context) string {
	if s.cfg.Demo {
		return "123456789012"
	}
	out, err := sts.NewFromConfig(s.cfg.AWS).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "unknown"
	}
	return aws.ToString(out.Account)
}

func (s *Server) regions(ctx context.Context) []string {
	if s.cfg.Demo {
		return []string{"us-east-1", "eu-west-1", "ap-southeast-2"}
	}
	s.mu.RLock()
	if len(s.cachedRegions) > 0 && time.Since(s.regionsAt) < 10*time.Minute {
		r := s.cachedRegions
		s.mu.RUnlock()
		return r
	}
	s.mu.RUnlock()
	disc := discovery.New(s.cfg.AWS, s.accountID(ctx), s.cfg.Region)
	regions, _ := disc.EnabledRegions(ctx)
	s.mu.Lock()
	s.cachedRegions = regions
	s.regionsAt = time.Now()
	s.mu.Unlock()
	return regions
}

// ---- scanning ----

// collect runs discovery + collectors for a scope, returning fresh (pre-lifecycle)
// findings, resources, which sources ran, and warnings.
func (s *Server) collect(ctx context.Context, scopeService, scopeResource string, deep bool) (fresh []types.Finding, resources []types.Resource, ran map[string]bool, warns []string) {
	accountID := s.accountID(ctx)
	regions := s.regions(ctx)
	ran = map[string]bool{}

	disc := discovery.New(s.cfg.AWS, accountID, s.cfg.Region)
	if scopeService != "" {
		resources, warns = disc.InventoryService(ctx, scopeService)
	} else {
		resources, warns = disc.Inventory(ctx)
	}

	own := collectors.NewOwnChecks(s.cfg.AWS, accountID, s.cfg.Region).
		WithRegions(regions).WithFilter(scopeService, scopeResource)
	of, ow := own.Collect(ctx)
	fresh = append(fresh, of...)
	warns = append(warns, ow...)
	ran["own-check"] = true

	// Prowler is read on full scans and deep scans, not quick audits.
	if scopeService == "" || deep {
		prowler := collectors.NewProwlerCollector(s.cfg.ProwlerResults, accountID, s.cfg.Region)
		pf, pw := prowler.Collect(ctx)
		pf = filterFindings(pf, scopeService, scopeResource)
		if len(pf) > 0 {
			fresh = append(fresh, pf...)
		}
		warns = append(warns, pw...)
		ran["prowler"] = true

		if s.cfg.ScoutResults != "" {
			sc := collectors.NewScoutSuiteCollector(s.cfg.ScoutResults, accountID, s.cfg.Region)
			sf, sw := sc.Collect(ctx)
			sf = filterFindings(sf, scopeService, scopeResource)
			if len(sf) > 0 {
				fresh = append(fresh, sf...)
				ran["scoutsuite"] = true
			}
			warns = append(warns, sw...)
		}
		if s.cfg.CSPResults != "" && (scopeService == "" || scopeService == "iam") {
			cs := collectors.NewCloudsplainingCollector(s.cfg.CSPResults, accountID, s.cfg.Region)
			cf, cw := cs.Collect(ctx)
			cf = filterFindings(cf, scopeService, scopeResource)
			if len(cf) > 0 {
				fresh = append(fresh, cf...)
				ran["cloudsplaining"] = true
			}
			warns = append(warns, cw...)
		}
	}
	return fresh, resources, ran, warns
}

// RunReview performs a full scan, reconciles against the latest, persists the
// result as canonical latest, writes a history point, and evaluates alerts.
func (s *Server) RunReview(ctx context.Context, _, _ string) (*types.PostureReview, error) {
	return s.scan(ctx, "", "", false, "full")
}

// RunAudit performs a scoped quick (or deep) audit, merging into latest.
func (s *Server) RunAudit(ctx context.Context, service, resource string, deep bool) (*types.PostureReview, error) {
	kind := "quick"
	if deep {
		kind = "deep"
	}
	return s.scan(ctx, service, resource, deep, kind)
}

func (s *Server) scan(ctx context.Context, scopeService, scopeResource string, deep bool, kind string) (*types.PostureReview, error) {
	start := time.Now()
	cfgSettings := s.st.getSettings(ctx)

	fresh, resources, ran, warns := s.collect(ctx, scopeService, scopeResource, deep)
	fresh, dupes := dedupe.Merge(fresh)

	// previous review for lifecycle
	prev, _ := s.store.Latest(ctx)
	var prevFindings []types.Finding
	if prev != nil {
		prevFindings = prev.Findings
	}
	accepted := risk.Active(s.st.listRisks(ctx), time.Now())

	scope := lifecycle.Scope{Service: scopeService, ResourceID: scopeResource, Ran: ran}
	live, changes := lifecycle.Reconcile(prevFindings, fresh, scope, time.Now(), accepted, 90*24*time.Hour)

	// join plans
	plans := s.st.listPlans(ctx)
	for i := range live {
		if p, ok := plans[live[i].Fingerprint]; ok {
			pc := p
			live[i].Plan = &pc
		}
	}

	// rank with configured rubric
	w := cfgSettings.Rubric.Weights
	for i := range live {
		live[i].RiskScore = ranking.ComputeRiskScoreW(live[i].Factors, w.Severity, w.Exposure, w.Reachability, w.Criticality)
	}
	live = ranking.RankFindings(live)

	// attack paths (full scans only; scoped audits keep prior paths)
	var paths []types.AttackPath
	if scopeService == "" {
		facts := s.collectFacts(ctx, resources, live)
		paths = attackpath.Compute(facts, live, cfgSettings.Paths)
		markOnPath(live, paths)
	} else if prev != nil {
		paths = prev.Paths
	}

	score := ranking.PostureScoreCfg(live, cfgSettings.Rubric.Penalty, cfgSettings.Rubric.PerSeverityCap)
	rating := ratingFromBands(score, cfgSettings.Rubric.Bands)

	// merge resources for scoped audits
	if scopeService != "" && prev != nil {
		resources = mergeResources(prev.Resources, resources, scopeService)
	}

	sourcesStatus := map[string]types.SourceStatus{}
	for src := range ran {
		sourcesStatus[src] = types.SourceStatus{Ran: true, At: time.Now(), Count: countBySource(live, src)}
	}

	review := &types.PostureReview{
		ReviewID: uuid.NewString(), AccountID: s.accountID(ctx), Regions: s.regions(ctx),
		Status: "completed", CreatedAt: time.Now().UTC(), DurationSeconds: time.Since(start).Seconds(),
		PostureScore: score, Rating: rating, Summary: summarize(live),
		Findings: live, Resources: resources, Paths: paths,
		SourcesRun: keys(ran), Warnings: warns,
		Changes: types.Changes{
			New: ids(changes.New), Fixed: ids(changes.Fixed), Regressed: ids(changes.Regressed),
			NewCount: len(changes.New), FixedCount: len(changes.Fixed), RegressedCount: len(changes.Regressed),
		},
		SourcesStatus: sourcesStatus, DuplicatesMerged: dupes, Scope: scopeTag(scopeService, scopeResource),
	}

	if err := s.store.Put(ctx, review); err != nil {
		log.Printf("store.Put: %v", err)
	}
	// history + alerts on full scans
	if scopeService == "" {
		s.st.putHistory(ctx, types.HistoryPoint{
			At: review.CreatedAt, ReviewID: review.ReviewID, Score: score, Rating: rating,
			Open: countOpen(live), BySeverity: review.Summary.BySeverity,
			New: review.Changes.NewCount, Fixed: review.Changes.FixedCount,
			Regressed: review.Changes.RegressedCount,
		})
		s.evaluateAlerts(ctx, cfgSettings, changes, paths, prev)
	}
	action := audit.ScanFull
	if kind == "quick" {
		action = audit.ScanQuick
	} else if kind == "deep" {
		action = audit.ScanDeepFinish
	}
	s.st.logActivity(ctx, audit.Entry{Actor: "system", Action: action, TargetType: "scope", Target: review.Scope})
	return review, nil
}

func (s *Server) collectFacts(ctx context.Context, resources []types.Resource, findings []types.Finding) attackpath.Facts {
	if s.cfg.Demo {
		return attackpath.Facts{Account: s.accountID(ctx)}
	}
	// Derive conservative facts from findings + resources (read-only, no extra calls
	// beyond discovery already done). Full fact collection via AWS is in discovery;
	// here we build a minimal, test-covered view to feed the pure engine.
	return buildFactsFromReview(s.accountID(ctx), resources, findings)
}

func (s *Server) evaluateAlerts(ctx context.Context, cfg settings.Settings, ch lifecycle.Changes, paths []types.AttackPath, prev *types.PostureReview) {
	if !cfg.Alerts.WebhookSet {
		return
	}
	var events []alerts.Event
	for _, f := range ch.New {
		if f.Severity == types.SevCritical && cfg.Alerts.Events["new_critical"] {
			events = append(events, alerts.Event{Kind: "new_critical", Fingerprint: f.Fingerprint, Title: f.Title})
		} else if f.Severity == types.SevHigh && cfg.Alerts.Events["new_high"] {
			events = append(events, alerts.Event{Kind: "new_high", Fingerprint: f.Fingerprint, Title: f.Title})
		}
	}
	for _, f := range ch.Regressed {
		if cfg.Alerts.Events["regressed"] {
			events = append(events, alerts.Event{Kind: "regressed", Fingerprint: f.Fingerprint, Title: f.Title})
		}
	}
	// suppress already-sent
	var toSend []alerts.Event
	for _, e := range events {
		if s.st.alertSent(ctx, e.SuppressKey()) {
			continue
		}
		toSend = append(toSend, e)
		s.st.markAlertSent(ctx, e.SuppressKey())
	}
	if len(toSend) == 0 {
		return
	}
	// The webhook value lives in a Secret-backed env; the sender validates it.
	webhook := envWebhook()
	if webhook == "" {
		return
	}
	sender := alerts.NewSender(webhook, nil)
	if cfg.Alerts.Mode == "digest" {
		_ = sender.Send(ctx, alerts.BuildDigest(toSend, s.cfg.PublicURL))
	} else {
		for _, e := range toSend {
			_ = sender.Send(ctx, alerts.BuildImmediate(e, s.cfg.PublicURL))
		}
	}
	s.st.logActivity(ctx, audit.Entry{Actor: "system", Action: audit.AlertSent, Detail: fmt.Sprintf("%d alert(s)", len(toSend))})
}

// ---- helpers ----

func filterFindings(fs []types.Finding, service, resource string) []types.Finding {
	if service == "" && resource == "" {
		return fs
	}
	var out []types.Finding
	for _, f := range fs {
		if service != "" && f.Service != service {
			continue
		}
		if resource != "" && f.ResourceID != resource {
			continue
		}
		out = append(out, f)
	}
	return out
}

func mergeResources(prev, cur []types.Resource, service string) []types.Resource {
	byID := map[string]types.Resource{}
	for _, r := range prev {
		if r.Service != service {
			byID[r.ID] = r
		}
	}
	for _, r := range cur {
		byID[r.ID] = r
	}
	out := make([]types.Resource, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	return out
}

func markOnPath(findings []types.Finding, paths []types.AttackPath) {
	onPath := map[string][]string{}
	for _, p := range paths {
		for _, fid := range p.FindingIDs {
			onPath[fid] = append(onPath[fid], p.ID)
		}
	}
	for i := range findings {
		if ps, ok := onPath[findings[i].ID]; ok {
			findings[i].OnPath = ps
		}
	}
}

func summarize(fs []types.Finding) types.PostureSummary {
	sum := types.PostureSummary{Total: len(fs), BySeverity: map[string]int{}, ByService: map[string]int{}, BySource: map[string]int{}}
	for _, f := range fs {
		sum.BySeverity[string(f.Severity)]++
		sum.ByService[f.Service]++
		if len(f.Sources) > 0 {
			for _, src := range f.Sources {
				sum.BySource[src.Source]++
			}
		} else {
			sum.BySource[f.Source]++
		}
	}
	return sum
}

func countBySource(fs []types.Finding, src string) int {
	n := 0
	for _, f := range fs {
		for _, s := range f.Sources {
			if s.Source == src {
				n++
				break
			}
		}
	}
	return n
}

func countOpen(fs []types.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Status == types.StatusOpen || f.Status == types.StatusRegressed {
			n++
		}
	}
	return n
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ids(fs []types.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func scopeTag(service, resource string) string {
	if resource != "" {
		return "resource:" + resource
	}
	if service != "" {
		return "service:" + service
	}
	return "account"
}

func ratingFromBands(score int, bands []settings.Band) string {
	best := "Critical"
	bestMin := -1
	for _, b := range bands {
		if score >= b.Min && b.Min >= bestMin {
			best = b.Name
			bestMin = b.Min
		}
	}
	return best
}

func envWebhook() string { return getenv("SLACK_WEBHOOK_URL") }

// small indirection so tests can stub (kept simple).
var getenv = func(k string) string { return osGetenv(k) }
