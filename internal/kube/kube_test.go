package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestClient points a Client at an httptest server (TLS skipped via the
// server's own client transport is not possible; instead we hand-roll host+http).
func newTestClient(srv *httptest.Server) *Client {
	return &Client{
		host:      srv.URL,
		token:     "test",
		namespace: "CodeSentinal.",
		http:      srv.Client(),
		available: true,
	}
}

func TestParseJobStatusStates(t *testing.T) {
	cases := map[string]string{
		`{"status":{"succeeded":1}}`: "completed",
		`{"status":{"failed":1}}`:    "failed",
		`{"status":{"active":1}}`:    "running",
		`{"status":{}}`:              "queued",
	}
	for body, want := range cases {
		st, err := parseJobStatus([]byte(body))
		if err != nil || st.State != want {
			t.Errorf("%s => %s (want %s) err=%v", body, st.State, want, err)
		}
	}
}

func TestCreateJobFromCronJobAndGet(t *testing.T) {
	var created bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/cronjobs/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"backoffLimit": 1}}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs"):
			created = true
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"metadata":{"name":"j1"}}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/jobs/"):
			_, _ = w.Write([]byte(`{"metadata":{"name":"j1"},"status":{"active":1}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := newTestClient(srv)
	if err := c.CreateJobFromCronJob(context.Background(), "CodeSentinal.-prowler", "j1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !created {
		t.Fatal("job was not POSTed")
	}
	st, err := c.GetJob(context.Background(), "j1")
	if err != nil || st.State != "running" {
		t.Fatalf("get job: %+v err=%v", st, err)
	}
}

func TestUnavailableWhenNoEnv(t *testing.T) {
	c := New()
	if c.Available() {
		t.Skip("running inside a cluster; skip")
	}
}
