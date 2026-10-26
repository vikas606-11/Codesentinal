// Package kube is a tiny in-cluster Kubernetes client (stdlib net/http only)
// used to run Prowler deep scans on demand by creating a Job from the CronJob
// (F15). It grants nothing on AWS and only touches the release namespace.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// JobRunner is the interface the API depends on (so handlers can be faked).
type JobRunner interface {
	Available() bool
	CreateJobFromCronJob(ctx context.Context, cronjob, jobName string) error
	GetJob(ctx context.Context, name string) (JobStatus, error)
	ListDeepScanJobs(ctx context.Context) ([]JobStatus, error)
}

// JobStatus is the subset of a Job's status we surface.
type JobStatus struct {
	Name      string
	Active    int
	Succeeded int
	Failed    int
	State     string // queued | running | completed | failed
	Message   string
}

// Client talks to the in-cluster API server.
type Client struct {
	host      string
	token     string
	namespace string
	http      *http.Client
	available bool
}

// New builds a Client from the in-cluster service account files. When not in a
// cluster (local/demo), Available() is false and the caller hides deep scan.
func New() *Client {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	c := &Client{}
	if host == "" || port == "" {
		return c
	}
	tokenB, err1 := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	caB, err2 := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	nsB, err3 := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err1 != nil || err2 != nil || err3 != nil {
		return c
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caB) {
		return c
	}
	c.host = "https://" + host + ":" + port
	c.token = strings.TrimSpace(string(tokenB))
	c.namespace = strings.TrimSpace(string(nsB))
	c.http = &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	c.available = true
	return c
}

func (c *Client) Available() bool { return c.available }

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.host+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.StatusCode, nil
}

// CreateJobFromCronJob copies the CronJob's jobTemplate into a new Job.
func (c *Client) CreateJobFromCronJob(ctx context.Context, cronjob, jobName string) error {
	cj, code, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/apis/batch/v1/namespaces/%s/cronjobs/%s", c.namespace, cronjob), nil)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("get cronjob %s: status %d", cronjob, code)
	}
	var parsed struct {
		Spec struct {
			JobTemplate struct {
				Spec json.RawMessage `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(cj, &parsed); err != nil {
		return err
	}
	ttl := int32(3600)
	job := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":        jobName,
			"namespace":   c.namespace,
			"labels":      map[string]string{"CodeSentinal./deep-scan": "true"},
			"annotations": map[string]string{"cronjob.kubernetes.io/instantiate": "manual"},
		},
		"spec": withTTL(parsed.Spec.JobTemplate.Spec, ttl),
	}
	body, _ := json.Marshal(job)
	_, code, err = c.do(ctx, http.MethodPost,
		fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs", c.namespace), body)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("create job: status %d", code)
	}
	return nil
}

func withTTL(spec json.RawMessage, ttl int32) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(spec, &m); err != nil || m == nil {
		m = map[string]any{}
	}
	m["ttlSecondsAfterFinished"] = ttl
	return m
}

// GetJob returns a Job's status mapped to our state machine.
func (c *Client) GetJob(ctx context.Context, name string) (JobStatus, error) {
	b, code, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", c.namespace, name), nil)
	if err != nil {
		return JobStatus{}, err
	}
	if code == 404 {
		return JobStatus{Name: name, State: "failed", Message: "job not found"}, nil
	}
	if code != 200 {
		return JobStatus{}, fmt.Errorf("get job: status %d", code)
	}
	return parseJobStatus(b)
}

// ListDeepScanJobs lists jobs labelled CodeSentinal./deep-scan=true.
func (c *Client) ListDeepScanJobs(ctx context.Context) ([]JobStatus, error) {
	b, code, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs?labelSelector=CodeSentinal./deep-scan=true", c.namespace), nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("list jobs: status %d", code)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	var out []JobStatus
	for _, it := range list.Items {
		if st, err := parseJobStatus(it); err == nil {
			out = append(out, st)
		}
	}
	return out, nil
}

func parseJobStatus(b []byte) (JobStatus, error) {
	var j struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Active    int `json:"active"`
			Succeeded int `json:"succeeded"`
			Failed    int `json:"failed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return JobStatus{}, err
	}
	st := JobStatus{Name: j.Metadata.Name, Active: j.Status.Active, Succeeded: j.Status.Succeeded, Failed: j.Status.Failed}
	switch {
	case j.Status.Succeeded > 0:
		st.State = "completed"
	case j.Status.Failed > 0:
		st.State = "failed"
	case j.Status.Active > 0:
		st.State = "running"
	default:
		st.State = "queued"
	}
	return st, nil
}
