// Package risk holds accepted-risk register logic (F4). Pure.
package risk

import (
	"fmt"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

const maxAhead = 365 * 24 * time.Hour

// Validate checks an accepted-risk entry.
func Validate(r types.AcceptedRisk, now time.Time) error {
	if len(r.Reason) < 10 || len(r.Reason) > 1000 {
		return fmt.Errorf("reason must be 10..1000 characters")
	}
	if r.Owner == "" {
		return fmt.Errorf("owner is required")
	}
	if r.ExpiresAt.IsZero() {
		return fmt.Errorf("expiry is required")
	}
	if r.ExpiresAt.Before(now) {
		return fmt.Errorf("expiry must be in the future")
	}
	if r.ExpiresAt.After(now.Add(maxAhead)) {
		return fmt.Errorf("expiry must be at most 365 days ahead")
	}
	if r.Fingerprint == "" {
		return fmt.Errorf("fingerprint is required")
	}
	return nil
}

// Active returns entries that have not expired.
func Active(all map[string]types.AcceptedRisk, now time.Time) map[string]types.AcceptedRisk {
	out := map[string]types.AcceptedRisk{}
	for k, v := range all {
		if now.Before(v.ExpiresAt) {
			out[k] = v
		}
	}
	return out
}

// Expired returns entries whose expiry has passed.
func Expired(all map[string]types.AcceptedRisk, now time.Time) []types.AcceptedRisk {
	var out []types.AcceptedRisk
	for _, v := range all {
		if !now.Before(v.ExpiresAt) {
			out = append(out, v)
		}
	}
	return out
}

// ExpiringWithin returns entries expiring within d (and not yet expired).
func ExpiringWithin(all map[string]types.AcceptedRisk, now time.Time, d time.Duration) []types.AcceptedRisk {
	var out []types.AcceptedRisk
	for _, v := range all {
		if now.Before(v.ExpiresAt) && v.ExpiresAt.Before(now.Add(d)) {
			out = append(out, v)
		}
	}
	return out
}
