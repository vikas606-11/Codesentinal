package store

import (
	"context"
	"testing"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func TestMemoryStoreLatestAndList(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	r1 := &types.PostureReview{ReviewID: "a", CreatedAt: time.Now().Add(-time.Hour)}
	r2 := &types.PostureReview{ReviewID: "b", CreatedAt: time.Now()}
	if err := m.Put(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if err := m.Put(ctx, r2); err != nil {
		t.Fatal(err)
	}

	latest, _ := m.Latest(ctx)
	if latest == nil || latest.ReviewID != "b" {
		t.Fatalf("latest = %+v, want b", latest)
	}
	got, _ := m.Get(ctx, "a")
	if got == nil || got.ReviewID != "a" {
		t.Fatalf("get a = %+v", got)
	}
	list, _ := m.List(ctx, 10)
	if len(list) != 2 || list[0].ReviewID != "b" {
		t.Fatalf("list = %+v, want [b a]", list)
	}
}
