package api

import (
	"context"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/audit"
	"github.com/sriramg-aivar/CodeSentinal./internal/report"
	"github.com/sriramg-aivar/CodeSentinal./internal/settings"
	"github.com/sriramg-aivar/CodeSentinal./internal/store"
	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// state wraps the KV store with typed helpers for v2 persistence.
type state struct{ kv store.KV }

func newState(s store.Store) *state { return &state{kv: s.KV()} }

// ---- settings ----

func (s *state) getSettings(ctx context.Context) settings.Settings {
	var out settings.Settings
	ok, err := s.kv.GetItem(ctx, "settings", "current", &out)
	if err != nil || !ok {
		return settings.Defaults()
	}
	return out
}

func (s *state) putSettings(ctx context.Context, v settings.Settings) error {
	return s.kv.PutItem(ctx, "settings", "current", v)
}

// ---- history ----

func (s *state) putHistory(ctx context.Context, h types.HistoryPoint) error {
	sk := h.At.UTC().Format(time.RFC3339Nano)
	return s.kv.PutItem(ctx, "history", sk, h)
}

func (s *state) listHistory(ctx context.Context, limit int) []types.HistoryPoint {
	var out []types.HistoryPoint
	_ = s.kv.Query(ctx, "history", "", limit, false, &out)
	return out
}

// ---- accepted risks ----

func (s *state) listRisks(ctx context.Context) map[string]types.AcceptedRisk {
	var rows []types.AcceptedRisk
	_ = s.kv.Query(ctx, "risk", "", 0, false, &rows)
	m := map[string]types.AcceptedRisk{}
	for _, r := range rows {
		m[r.Fingerprint] = r
	}
	return m
}

func (s *state) putRisk(ctx context.Context, r types.AcceptedRisk) error {
	return s.kv.PutItem(ctx, "risk", r.Fingerprint, r)
}

func (s *state) deleteRisk(ctx context.Context, fp string) error {
	return s.kv.DeleteItem(ctx, "risk", fp)
}

// ---- plans ----

func (s *state) listPlans(ctx context.Context) map[string]types.Plan {
	type planRow struct {
		Fingerprint string     `json:"fingerprint"`
		Plan        types.Plan `json:"plan"`
	}
	var rows []planRow
	_ = s.kv.Query(ctx, "plan", "", 0, false, &rows)
	m := map[string]types.Plan{}
	for _, r := range rows {
		m[r.Fingerprint] = r.Plan
	}
	return m
}

func (s *state) putPlan(ctx context.Context, fp string, p types.Plan) error {
	return s.kv.PutItem(ctx, "plan", fp, map[string]any{"fingerprint": fp, "plan": p})
}

// ---- reports ----

type reportRecord struct {
	Meta report.Meta `json:"meta"`
	Data report.Data `json:"data"`
}

func (s *state) putReport(ctx context.Context, r reportRecord) error {
	return s.kv.PutItem(ctx, "report", r.Meta.ID, r)
}

func (s *state) getReport(ctx context.Context, id string) (reportRecord, bool) {
	var r reportRecord
	ok, _ := s.kv.GetItem(ctx, "report", id, &r)
	return r, ok
}

func (s *state) listReports(ctx context.Context) []report.Meta {
	var rows []reportRecord
	_ = s.kv.Query(ctx, "report", "", 0, true, &rows)
	var out []report.Meta
	for _, r := range rows {
		out = append(out, r.Meta)
	}
	return out
}

// ---- activity log ----

func (s *state) logActivity(ctx context.Context, e audit.Entry) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	sk := audit.SortKey(e.At, randID())
	_ = s.kv.PutItem(ctx, "activity", sk, e)
}

func (s *state) listActivity(ctx context.Context, limit int) []audit.Entry {
	var out []audit.Entry
	_ = s.kv.Query(ctx, "activity", "", limit, true, &out)
	return out
}

// ---- alert suppression ----

func (s *state) alertSent(ctx context.Context, key string) bool {
	var seen struct {
		At time.Time `json:"at"`
	}
	ok, _ := s.kv.GetItem(ctx, "alert", key, &seen)
	return ok
}

func (s *state) markAlertSent(ctx context.Context, key string) {
	_ = s.kv.PutItem(ctx, "alert", key, map[string]any{"at": time.Now().UTC()})
}
