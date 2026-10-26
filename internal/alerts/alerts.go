// Package alerts builds and sends Slack alert messages with suppression and
// strict URL validation (F12). Pure logic plus a small net/http sender.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event is one alertable occurrence.
type Event struct {
	Kind        string // new_critical | new_high | regressed | new_path | risk_expiring | scan_failed
	Fingerprint string // for suppression keying
	Title       string
	Detail      string
}

// SuppressKey is the stable key used to avoid re-alerting.
func (e Event) SuppressKey() string { return e.Kind + "|" + e.Fingerprint }

var allowedHostsDefault = map[string]bool{"hooks.slack.com": true}

// ValidateWebhook checks a Slack webhook URL: https, allowed host, no userinfo,
// not a private IP literal.
func ValidateWebhook(raw string, extraHosts []string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook must be https")
	}
	if u.User != nil {
		return fmt.Errorf("webhook must not contain userinfo")
	}
	host := u.Hostname()
	allowed := allowedHostsDefault[host]
	for _, h := range extraHosts {
		if h == host {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("webhook host %q not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
			return fmt.Errorf("webhook must not point at a private IP")
		}
	}
	return nil
}

// Message is the Slack JSON payload.
type Message struct {
	Text string `json:"text"`
}

// BuildImmediate renders a single-event message. publicURL (optional) is linked.
func BuildImmediate(e Event, publicURL string) Message {
	var b strings.Builder
	b.WriteString(icon(e.Kind) + " *" + title(e.Kind) + "*\n")
	b.WriteString(e.Title)
	if e.Detail != "" {
		b.WriteString("\n" + e.Detail)
	}
	if publicURL != "" {
		b.WriteString("\n" + publicURL)
	}
	return Message{Text: b.String()}
}

// BuildDigest groups many events from one scan into one message.
func BuildDigest(events []Event, publicURL string) Message {
	if len(events) == 0 {
		return Message{}
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Kind]++
	}
	var b strings.Builder
	b.WriteString(":shield: *CodeSentinal. scan summary*\n")
	for _, k := range []string{"new_critical", "new_high", "regressed", "new_path", "risk_expiring", "scan_failed"} {
		if counts[k] > 0 {
			b.WriteString(fmt.Sprintf("• %s: %d\n", title(k), counts[k]))
		}
	}
	if publicURL != "" {
		b.WriteString(publicURL)
	}
	return Message{Text: strings.TrimRight(b.String(), "\n")}
}

func icon(kind string) string {
	switch kind {
	case "new_critical", "scan_failed":
		return ":rotating_light:"
	case "new_high", "regressed", "new_path":
		return ":warning:"
	default:
		return ":information_source:"
	}
}

func title(kind string) string {
	switch kind {
	case "new_critical":
		return "New critical finding"
	case "new_high":
		return "New high finding"
	case "regressed":
		return "Regressed finding"
	case "new_path":
		return "New attack path"
	case "risk_expiring":
		return "Accepted risk expiring"
	case "scan_failed":
		return "Scan failed"
	default:
		return kind
	}
}

// Sender posts messages to a validated Slack webhook.
type Sender struct {
	webhook    string
	extraHosts []string
	client     *http.Client
}

func NewSender(webhook string, extraHosts []string) *Sender {
	return &Sender{webhook: webhook, extraHosts: extraHosts, client: &http.Client{Timeout: 5 * time.Second}}
}

// Send validates the URL again (defence in depth) then posts the message, with
// one retry. Body is capped well under 40 KB by construction.
func (s *Sender) Send(ctx context.Context, m Message) error {
	if err := ValidateWebhook(s.webhook, s.extraHosts); err != nil {
		return err
	}
	body, _ := json.Marshal(m)
	if len(body) > 40*1024 {
		body = body[:40*1024]
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhook, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return lastErr
}
