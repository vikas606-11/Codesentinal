package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sriramg-aivar/CodeSentinal./internal/alerts"
	"github.com/sriramg-aivar/CodeSentinal./internal/audit"
	"github.com/sriramg-aivar/CodeSentinal./internal/fixes"
	"github.com/sriramg-aivar/CodeSentinal./internal/report"
	"github.com/sriramg-aivar/CodeSentinal./internal/risk"
	"github.com/sriramg-aivar/CodeSentinal./internal/settings"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Routes wires the API with auth + security headers.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	// public
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/api/v1/health", s.health)
	mux.HandleFunc("/api/v1/meta", s.meta)
	mux.HandleFunc("/api/v1/auth/login", s.login)
	mux.HandleFunc("/api/v1/auth/status", s.authStatus)
	// protected
	mux.HandleFunc("/api/v1/review", s.runReview)
	mux.HandleFunc("/api/v1/review/latest", s.getLatest)
	mux.HandleFunc("/api/v1/reviews", s.listReviews)
	mux.HandleFunc("/api/v1/overview", s.overview)
	mux.HandleFunc("/api/v1/services", s.getServices)
	mux.HandleFunc("/api/v1/regions", s.getRegions)
	mux.HandleFunc("/api/v1/resources", s.getResources)
	mux.HandleFunc("/api/v1/resource", s.getResource)
	mux.HandleFunc("/api/v1/findings", s.getFindings)
	mux.HandleFunc("/api/v1/finding", s.getFinding)
	mux.HandleFunc("/api/v1/finding/plan", s.putPlan)
	mux.HandleFunc("/api/v1/risks", s.risks)
	mux.HandleFunc("/api/v1/paths", s.getPaths)
	mux.HandleFunc("/api/v1/history", s.getHistory)
	mux.HandleFunc("/api/v1/audit", s.auditHandler)
	mux.HandleFunc("/api/v1/scans/deep", s.deepScan)
	mux.HandleFunc("/api/v1/scans/", s.deepScanStatus)
	mux.HandleFunc("/api/v1/reports", s.reports)
	mux.HandleFunc("/api/v1/reports/", s.reportByID)
	mux.HandleFunc("/api/v1/activity", s.activity)
	mux.HandleFunc("/api/v1/settings", s.settingsHandler)
	mux.HandleFunc("/api/v1/explain", s.explain)
	mux.HandleFunc("/api/v1/integrations", s.integrations)

	return securityHeaders(s.cors(s.authMiddleware(mux)))
}

// ---- middleware ----

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

func isPublic(p string) bool {
	switch p {
	case "/health", "/api/v1/health", "/api/v1/meta", "/api/v1/auth/login", "/api/v1/auth/status":
		return true
	}
	return false
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.AuthEnabled || isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		tok := bearer(r)
		if tok == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized", "role": "superadmin"})
			return
		}
		if _, err := s.cfg.Sessions.Verify(tok); err != nil {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return "" // no ?token= fallback (F14)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) cors(h http.Handler) http.Handler {
	origin := osGetenv("ALLOWED_ORIGIN")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ---- public handlers ----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "service": "CodeSentinal.", "store": s.store.Kind()})
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	kubeAvail := s.cfg.Kube != nil && s.cfg.Kube.Available()
	writeJSON(w, 200, map[string]any{
		"version": s.cfg.Version, "store": s.store.Kind(), "demo": s.cfg.Demo,
		"local": s.cfg.Local, "kube_available": kubeAvail, "auth_required": s.cfg.AuthEnabled,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	ip := s.clientIP(r)
	now := time.Now()
	if ok, retry := s.cfg.Throttle.Allow(ip, now); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		writeJSON(w, 429, map[string]string{"error": "too many attempts"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)

	if !s.cfg.AuthEnabled {
		writeJSON(w, 200, map[string]string{"token": s.cfg.Sessions.Issue("superadmin"), "role": "superadmin"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(s.cfg.Password)) != 1 {
		s.cfg.Throttle.Record(ip, now)
		s.st.logActivity(r.Context(), audit.Entry{Actor: "anonymous", Action: audit.LoginFailure, IP: ip})
		writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.LoginSuccess, IP: ip})
	writeJSON(w, 200, map[string]string{"token": s.cfg.Sessions.Issue("superadmin"), "role": "superadmin"})
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"auth_required": s.cfg.AuthEnabled, "role": "superadmin"})
}

// ---- review / overview ----

func (s *Server) runReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "a scan is already running"})
		return
	}
	s.scanning = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.scanning = false; s.mu.Unlock() }()

	rv, err := s.RunReview(r.Context(), "", "")
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, rv)
}

func (s *Server) getLatest(w http.ResponseWriter, r *http.Request) {
	rv, _ := s.store.Latest(r.Context())
	if rv == nil {
		writeJSON(w, 404, map[string]string{"error": "no review yet"})
		return
	}
	writeJSON(w, 200, rv)
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	rv, _ := s.store.Latest(r.Context())
	hist := s.st.listHistory(r.Context(), 30)
	if rv == nil {
		writeJSON(w, 200, map[string]any{"has_review": false, "trend": hist})
		return
	}
	var prevScore *int
	if len(hist) >= 2 {
		p := hist[1].Score
		prevScore = &p
	}
	// top 5 fixes
	var top []map[string]any
	for _, f := range rv.Findings {
		if f.Status == types.StatusFixed || f.Status == types.StatusAccepted {
			continue
		}
		item := map[string]any{"finding": f}
		if fx, ok := fixes.For(f); ok {
			item["fix"] = fx
		}
		top = append(top, item)
		if len(top) >= 5 {
			break
		}
	}
	writeJSON(w, 200, map[string]any{
		"has_review": true, "score": rv.PostureScore, "rating": rv.Rating,
		"previous_score": prevScore, "trend": hist, "by_severity": rv.Summary.BySeverity,
		"changes": rv.Changes, "top_fixes": top, "paths": len(rv.Paths),
		"accepted": countAccepted(rv.Findings), "sources_status": rv.SourcesStatus,
		"duplicates_merged": rv.DuplicatesMerged, "account": rv.AccountID, "regions": rv.Regions,
	})
}

func (s *Server) listReviews(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	reviews, _ := s.store.List(r.Context(), limit)
	type item struct {
		ReviewID     string    `json:"review_id"`
		CreatedAt    time.Time `json:"created_at"`
		PostureScore int       `json:"posture_score"`
		Rating       string    `json:"rating"`
		Total        int       `json:"total_findings"`
	}
	var out []item
	for _, rv := range reviews {
		out = append(out, item{rv.ReviewID, rv.CreatedAt, rv.PostureScore, rv.Rating, rv.Summary.Total})
	}
	writeJSON(w, 200, map[string]any{"reviews": out})
}

// ---- navigation ----

func (s *Server) getServices(w http.ResponseWriter, r *http.Request) {
	rv, _ := s.store.Latest(r.Context())
	resCount, findCount := map[string]int{}, map[string]int{}
	if rv != nil {
		for _, res := range rv.Resources {
			resCount[res.Service]++
		}
		for _, f := range rv.Findings {
			if f.Status != types.StatusFixed {
				findCount[f.Service]++
			}
		}
	}
	out := make([]types.ServiceInfo, 0, len(supportedServices))
	for _, svc := range supportedServices {
		svc.ResourceCount = resCount[svc.Key]
		svc.FindingCount = findCount[svc.Key]
		out = append(out, svc)
	}
	writeJSON(w, 200, map[string]any{"services": out, "has_review": rv != nil})
}

func (s *Server) getRegions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"regions": s.regions(r.Context())})
}

func (s *Server) getResources(w http.ResponseWriter, r *http.Request) {
	rv, _ := s.store.Latest(r.Context())
	if rv == nil {
		writeJSON(w, 404, map[string]string{"error": "no review yet — run an audit first"})
		return
	}
	svc := r.URL.Query().Get("service")
	region := r.URL.Query().Get("region")
	rtype := r.URL.Query().Get("type")

	findByResource := map[string]int{}
	for _, f := range rv.Findings {
		if f.Status != types.StatusFixed {
			findByResource[f.ResourceID]++
		}
	}
	regionsSet := map[string]struct{}{}
	typesSet := map[string]struct{}{}
	var resources []types.Resource
	for _, res := range rv.Resources {
		if svc != "" && res.Service != svc {
			continue
		}
		regionsSet[res.Region] = struct{}{}
		typesSet[res.Type] = struct{}{}
		if region != "" && res.Region != region {
			continue
		}
		if rtype != "" && res.Type != rtype {
			continue
		}
		resources = append(resources, res)
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Region != resources[j].Region {
			return resources[i].Region < resources[j].Region
		}
		return resources[i].Name < resources[j].Name
	})
	type resWithCount struct {
		types.Resource
		FindingCount int `json:"finding_count"`
	}
	enriched := make([]resWithCount, 0, len(resources))
	for _, res := range resources {
		enriched = append(enriched, resWithCount{res, findByResource[res.ID]})
	}
	writeJSON(w, 200, map[string]any{
		"service": svc, "region": region, "type": rtype,
		"regions": sortedKeys(regionsSet), "types": sortedKeys(typesSet), "resources": enriched,
	})
}

func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "id required"})
		return
	}
	rv, _ := s.store.Latest(r.Context())
	if rv == nil {
		writeJSON(w, 404, map[string]string{"error": "no review yet"})
		return
	}
	var resource *types.Resource
	for i := range rv.Resources {
		if rv.Resources[i].ID == id {
			resource = &rv.Resources[i]
			break
		}
	}
	var findings []types.Finding
	for _, f := range rv.Findings {
		if f.ResourceID == id {
			findings = append(findings, f)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].RiskScore > findings[j].RiskScore })
	writeJSON(w, 200, map[string]any{"review_id": rv.ReviewID, "resource": resource, "findings": findings, "count": len(findings)})
}

// ---- findings ----

func (s *Server) getFindings(w http.ResponseWriter, r *http.Request) {
	rv, _ := s.store.Latest(r.Context())
	if rv == nil {
		writeJSON(w, 200, map[string]any{"total": 0, "items": []any{}})
		return
	}
	q := r.URL.Query()
	var items []types.Finding
	for _, f := range rv.Findings {
		if v := q.Get("status"); v != "" && string(f.Status) != v {
			continue
		}
		if v := q.Get("severity"); v != "" && string(f.Severity) != v {
			continue
		}
		if v := q.Get("service"); v != "" && f.Service != v {
			continue
		}
		if v := q.Get("region"); v != "" && f.Region != v {
			continue
		}
		if v := q.Get("source"); v != "" && !hasSource(f, v) {
			continue
		}
		if v := q.Get("on_path"); v == "true" && len(f.OnPath) == 0 {
			continue
		}
		if v := q.Get("q"); v != "" && !strings.Contains(strings.ToLower(f.Title), strings.ToLower(v)) {
			continue
		}
		items = append(items, f)
	}
	switch q.Get("sort") {
	case "age":
		sort.SliceStable(items, func(i, j int) bool { return items[i].AgeDays > items[j].AgeDays })
	case "seen":
		sort.SliceStable(items, func(i, j int) bool { return items[i].LastSeen.After(items[j].LastSeen) })
	default:
		sort.SliceStable(items, func(i, j int) bool { return items[i].RiskScore > items[j].RiskScore })
	}
	total := len(items)
	limit := 200
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	writeJSON(w, 200, map[string]any{"total": total, "items": items})
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rv, _ := s.store.Latest(r.Context())
	if rv == nil || id == "" {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	for _, f := range rv.Findings {
		if f.ID == id {
			resp := map[string]any{"finding": f}
			if fx, ok := fixes.For(f); ok {
				resp["fix"] = fx
			}
			resp["explanation"] = s.explainer.Explain(r.Context(), f)
			writeJSON(w, 200, resp)
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "finding not found"})
}

func (s *Server) putPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "PUT only", 405)
		return
	}
	var body struct {
		ID      string `json:"id"`
		Owner   string `json:"owner"`
		Effort  string `json:"effort"`
		DueDate string `json:"due_date"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "id required"})
		return
	}
	if body.Effort != "" && body.Effort != "S" && body.Effort != "M" && body.Effort != "L" {
		writeJSON(w, 400, map[string]string{"error": "effort must be S, M or L"})
		return
	}
	if len(body.Owner) > 80 {
		writeJSON(w, 400, map[string]string{"error": "owner too long"})
		return
	}
	p := types.Plan{Owner: body.Owner, Effort: body.Effort, UpdatedAt: time.Now().UTC()}
	if body.DueDate != "" {
		p.DueDate = &body.DueDate
	}
	if err := s.st.putPlan(r.Context(), body.ID, p); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.PlanUpdate, TargetType: "finding", Target: body.ID})
	writeJSON(w, 200, map[string]any{"ok": true, "plan": p})
}

// ---- risks ----

func (s *Server) risks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		m := s.st.listRisks(r.Context())
		var out []types.AcceptedRisk
		for _, v := range m {
			out = append(out, v)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
		writeJSON(w, 200, map[string]any{"risks": out})
	case http.MethodPost:
		var ar types.AcceptedRisk
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ar); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad body"})
			return
		}
		ar.CreatedAt = time.Now().UTC()
		ar.CreatedBy = "superadmin"
		if err := risk.Validate(ar, time.Now()); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := s.st.putRisk(r.Context(), ar); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.RiskAccept, TargetType: "finding", Target: ar.Fingerprint})
		writeJSON(w, 200, map[string]any{"ok": true})
	case http.MethodDelete:
		fp := r.URL.Query().Get("fingerprint")
		if fp == "" {
			writeJSON(w, 400, map[string]string{"error": "fingerprint required"})
			return
		}
		_ = s.st.deleteRisk(r.Context(), fp)
		s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.RiskRevoke, TargetType: "finding", Target: fp})
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ---- paths / history ----

func (s *Server) getPaths(w http.ResponseWriter, r *http.Request) {
	rv, _ := s.store.Latest(r.Context())
	if rv == nil {
		writeJSON(w, 200, map[string]any{"paths": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{"paths": rv.Paths})
}

func (s *Server) getHistory(w http.ResponseWriter, r *http.Request) {
	limit := 60
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	writeJSON(w, 200, map[string]any{"history": s.st.listHistory(r.Context(), limit)})
}

// ---- audit (quick scan) ----

func (s *Server) auditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	service := r.URL.Query().Get("service")
	resource := r.URL.Query().Get("resource")
	rv, err := s.RunAudit(r.Context(), service, resource, false)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	scoped := filterFindings(rv.Findings, service, resource)
	writeJSON(w, 200, map[string]any{
		"kind": "quick", "review_id": rv.ReviewID, "service": service, "resource": resource,
		"findings": scoped, "count": len(scoped), "sources_run": rv.SourcesRun,
		"changes": rv.Changes, "scanned_at": rv.CreatedAt,
	})
}

// ---- deep scan ----

func (s *Server) deepScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	if s.cfg.Kube == nil || !s.cfg.Kube.Available() {
		writeJSON(w, 501, map[string]string{"error": "deep scan not available (no cluster)"})
		return
	}
	// single active deep scan
	jobs, _ := s.cfg.Kube.ListDeepScanJobs(r.Context())
	for _, j := range jobs {
		if j.State == "running" || j.State == "queued" {
			writeJSON(w, 409, map[string]string{"error": "a deep scan is already active"})
			return
		}
	}
	runID := randID()
	jobName := "CodeSentinal.-prowler-ondemand-" + runID
	if err := s.cfg.Kube.CreateJobFromCronJob(r.Context(), s.cfg.ProwlerCronJob, jobName); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	s.deepScans[runID] = jobName
	s.mu.Unlock()
	s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.ScanDeepStart, Target: jobName})
	writeJSON(w, 202, map[string]string{"run_id": runID, "job_name": jobName})
}

func (s *Server) deepScanStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	if id == "" || s.cfg.Kube == nil {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	s.mu.RLock()
	jobName := s.deepScans[id]
	s.mu.RUnlock()
	if jobName == "" {
		writeJSON(w, 404, map[string]string{"error": "unknown run"})
		return
	}
	st, err := s.cfg.Kube.GetJob(r.Context(), jobName)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	// on first completion, ingest
	if st.State == "completed" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			_, _ = s.RunAudit(ctx, "", "", true)
		}()
	}
	writeJSON(w, 200, map[string]any{"state": st.State, "message": st.Message})
}

// ---- reports ----

func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"reports": s.st.listReports(r.Context())})
	case http.MethodPost:
		var body struct {
			Scope    string `json:"scope"`
			Service  string `json:"service"`
			Resource string `json:"resource"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
		scope := "account"
		if body.Scope == "service" && body.Service != "" {
			scope = "service:" + body.Service
		} else if body.Scope == "resource" && body.Resource != "" {
			scope = "resource:" + body.Resource
		}
		rv, _ := s.store.Latest(r.Context())
		cfg := s.st.getSettings(r.Context())
		risks := mapToSlice(risk.Active(s.st.listRisks(r.Context()), time.Now()))
		data := report.Build(report.BuildInput{
			Review: rv, History: s.st.listHistory(r.Context(), 30), Risks: risks,
			MSPName: cfg.Branding.MSPName, ClientName: cfg.Branding.ClientName,
			LogoDataURI: cfg.Branding.LogoDataURI, Reviewer: cfg.Reviewer, Scope: scope,
		})
		data.Watermark = "DRAFT, not reviewed"
		rec := reportRecord{
			Meta: report.Meta{ID: uuid.NewString(), Scope: scope, Version: 1,
				Status: report.StatusDraft, CreatedAt: time.Now().UTC(), CreatedBy: "superadmin"},
			Data: data,
		}
		_ = s.st.putReport(r.Context(), rec)
		s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.ReportCreate, Target: rec.Meta.ID})
		writeJSON(w, 200, rec.Meta)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) reportByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	rec, ok := s.st.getReport(r.Context(), id)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "report not found"})
		return
	}
	// /reports/{id}
	if len(parts) == 1 {
		writeJSON(w, 200, map[string]any{"meta": rec.Meta, "preview": rec.Data.Summary})
		return
	}
	action := parts[1]
	switch action {
	case "download":
		s.downloadReport(w, r, rec)
	case "submit", "approve", "reject":
		s.transitionReport(w, r, rec, action)
	default:
		writeJSON(w, 404, map[string]string{"error": "unknown report action"})
	}
}

func (s *Server) transitionReport(w http.ResponseWriter, r *http.Request, rec reportRecord, action string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var body struct {
		Note     string `json:"note"`
		Reviewer string `json:"reviewer"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
	reviewer := body.Reviewer
	if reviewer == "" {
		reviewer = s.st.getSettings(r.Context()).Reviewer
	}
	next, err := report.Transition(rec.Meta.Status, action, reviewer, body.Note)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	rec.Meta.Status = next
	rec.Meta.Reviewer = reviewer
	rec.Meta.ReviewNote = body.Note
	now := time.Now().UTC()
	rec.Meta.ReviewedAt = &now
	rec.Data.Status = string(next)
	rec.Data.Reviewer = reviewer
	rec.Data.ReviewNote = body.Note
	if next == report.StatusApproved {
		rec.Data.Watermark = ""
	}
	_ = s.st.putReport(r.Context(), rec)
	act := map[string]string{"submit": audit.ReportSubmit, "approve": audit.ReportApprove, "reject": audit.ReportReject}[action]
	s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: act, Target: rec.Meta.ID})
	writeJSON(w, 200, rec.Meta)
}

func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request, rec reportRecord) {
	format := r.URL.Query().Get("format")
	if rec.Meta.Status != report.StatusApproved && rec.Data.Watermark == "" {
		rec.Data.Watermark = "DRAFT, not reviewed"
	}
	var body []byte
	var ctype, ext string
	switch format {
	case "md":
		body, ctype, ext = report.RenderMarkdown(rec.Data), "text/markdown", "md"
	case "html":
		body, ctype, ext = report.RenderHTML(rec.Data), "text/html", "html"
	default:
		b, err := report.RenderDOCX(rec.Data)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		body, ctype, ext = b, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"
	}
	s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.ReportDownload, Target: rec.Meta.ID, Detail: ext})
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", "attachment; filename=\"CodeSentinal.-report-"+safeName(rec.Meta.ID)+"."+ext+"\"")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

// ---- activity ----

func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries := s.st.listActivity(r.Context(), limit)
	if a := r.URL.Query().Get("action"); a != "" {
		entries = audit.FilterAction(entries, a)
	}
	switch r.URL.Query().Get("format") {
	case "csv":
		b, _ := audit.ExportCSV(entries)
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"CodeSentinal.-activity.csv\"")
		_, _ = w.Write(b)
	case "json":
		b, _ := audit.ExportJSON(entries)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"CodeSentinal.-activity.json\"")
		_, _ = w.Write(b)
	default:
		writeJSON(w, 200, map[string]any{"entries": entries})
	}
}

// ---- settings ----

func (s *Server) settingsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cur := s.st.getSettings(r.Context())
		// never return the webhook value
		cur.Alerts.WebhookSet = envWebhook() != "" || cur.Alerts.WebhookSet
		writeJSON(w, 200, cur)
	case http.MethodPut:
		var in settings.Settings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad body"})
			return
		}
		if err := in.Validate(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := settings.ValidateLogo(in.Branding.LogoDataURI); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		old := s.st.getSettings(r.Context())
		if err := s.st.putSettings(r.Context(), in); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		s.st.logActivity(r.Context(), audit.Entry{Actor: "superadmin", Action: audit.SettingsUpdate,
			Detail: strings.Join(settings.ChangedKeys(old, in), ",")})
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ---- explain / integrations ----

func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	reviewID := r.URL.Query().Get("review")
	findingID := r.URL.Query().Get("finding")
	rv, _ := s.store.Get(r.Context(), reviewID)
	if rv == nil {
		rv, _ = s.store.Latest(r.Context())
	}
	if rv == nil {
		writeJSON(w, 404, map[string]string{"error": "review not found"})
		return
	}
	for _, f := range rv.Findings {
		if f.ID == findingID {
			writeJSON(w, 200, s.explainer.Explain(r.Context(), f))
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "finding not found"})
}

func (s *Server) integrations(w http.ResponseWriter, r *http.Request) {
	note := "This is a paid AWS service the client enables. Check current AWS pricing before enabling. CodeSentinal. only reads findings."
	writeJSON(w, 200, map[string]any{"integrations": []types.Integration{
		{Key: "guardduty", Name: "Amazon GuardDuty", Enabled: false, Available: false,
			Description: "Continuous threat detection (active threats, not just misconfig).", Note: note},
		{Key: "securityhub", Name: "AWS Security Hub", Enabled: false, Available: false,
			Description: "Aggregated findings and compliance standards.", Note: note},
		{Key: "inspector", Name: "Amazon Inspector", Enabled: false, Available: false,
			Description: "Automated vulnerability (CVE) scanning for workloads.", Note: note},
	}})
}

// ---- small helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func hasSource(f types.Finding, src string) bool {
	for _, s := range f.Sources {
		if s.Source == src {
			return true
		}
	}
	return f.Source == src
}

func countAccepted(fs []types.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Status == types.StatusAccepted {
			n++
		}
	}
	return n
}

func sortedKeys(m map[string]struct{}) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mapToSlice(m map[string]types.AcceptedRisk) []types.AcceptedRisk {
	var out []types.AcceptedRisk
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "report"
	}
	return b.String()
}

// unused alert reference keeps the import when webhook disabled
var _ = alerts.ValidateWebhook
