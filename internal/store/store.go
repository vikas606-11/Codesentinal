// Package store persists posture reviews so they survive pod restarts and
// multiple replicas. DynamoDB is the primary backend (serverless, cheap);
// an in-memory store is the fallback so the product always works.
package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Store persists and retrieves reviews.
type Store interface {
	Put(ctx context.Context, r *types.PostureReview) error
	Get(ctx context.Context, id string) (*types.PostureReview, error)
	Latest(ctx context.Context) (*types.PostureReview, error)
	List(ctx context.Context, limit int) ([]*types.PostureReview, error)
	Kind() string
	KV() KV
}

// KV is a generic key/value sub-store for v2 state (history, risks, plans,
// reports, activity, settings, lease, explain cache).
type KV interface {
	PutItem(ctx context.Context, pk, sk string, v any) error
	GetItem(ctx context.Context, pk, sk string, out any) (bool, error)
	Query(ctx context.Context, pk, skPrefix string, limit int, newestFirst bool, out any) error
	DeleteItem(ctx context.Context, pk, sk string) error
	AcquireLease(ctx context.Context, name, owner string, ttl time.Duration) (bool, error)
}

// Memory is an in-memory Store (used when DynamoDB is not configured).
type Memory struct {
	mu    sync.RWMutex
	byID  map[string]*types.PostureReview
	order []string // review ids, newest last
	kv    *memKV
}

func NewMemory() *Memory {
	return &Memory{byID: map[string]*types.PostureReview{}}
}

func (m *Memory) Kind() string { return "memory" }

func (m *Memory) Put(_ context.Context, r *types.PostureReview) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[r.ReviewID]; !ok {
		m.order = append(m.order, r.ReviewID)
	}
	m.byID[r.ReviewID] = r
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*types.PostureReview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byID[id], nil
}

func (m *Memory) Latest(_ context.Context) (*types.PostureReview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.order) == 0 {
		return nil, nil
	}
	return m.byID[m.order[len(m.order)-1]], nil
}

func (m *Memory) List(_ context.Context, limit int) ([]*types.PostureReview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*types.PostureReview
	for i := len(m.order) - 1; i >= 0; i-- {
		out = append(out, m.byID[m.order[i]])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// ---- Memory KV ----

type memKV struct {
	mu     sync.RWMutex
	items  map[string][]byte // "pk\x00sk" -> json
	leases map[string]memLease
}

type memLease struct {
	owner   string
	expires time.Time
}

func (m *Memory) KV() KV {
	if m.kv == nil {
		m.kv = &memKV{items: map[string][]byte{}, leases: map[string]memLease{}}
	}
	return m.kv
}

func mk(pk, sk string) string { return pk + "\x00" + sk }

func (k *memKV) PutItem(_ context.Context, pk, sk string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.items[mk(pk, sk)] = b
	return nil
}

func (k *memKV) GetItem(_ context.Context, pk, sk string, out any) (bool, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	b, ok := k.items[mk(pk, sk)]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}

// Query decodes all items with the given pk whose sk starts with skPrefix into
// out (a pointer to a slice). newestFirst sorts by sk descending.
func (k *memKV) Query(_ context.Context, pk, skPrefix string, limit int, newestFirst bool, out any) error {
	k.mu.RLock()
	type kv struct {
		sk string
		b  []byte
	}
	var rows []kv
	prefix := pk + "\x00" + skPrefix
	for key, b := range k.items {
		if strings.HasPrefix(key, prefix) {
			rows = append(rows, kv{strings.SplitN(key, "\x00", 2)[1], b})
		}
	}
	k.mu.RUnlock()

	sort.Slice(rows, func(i, j int) bool {
		if newestFirst {
			return rows[i].sk > rows[j].sk
		}
		return rows[i].sk < rows[j].sk
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	arr := make([]json.RawMessage, 0, len(rows))
	for _, r := range rows {
		arr = append(arr, json.RawMessage(r.b))
	}
	joined, _ := json.Marshal(arr)
	return json.Unmarshal(joined, out)
}

func (k *memKV) DeleteItem(_ context.Context, pk, sk string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.items, mk(pk, sk))
	return nil
}

func (k *memKV) AcquireLease(_ context.Context, name, owner string, ttl time.Duration) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	l, ok := k.leases[name]
	if ok && now.Before(l.expires) && l.owner != owner {
		return false, nil
	}
	k.leases[name] = memLease{owner: owner, expires: now.Add(ttl)}
	return true, nil
}
