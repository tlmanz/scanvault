package usecases

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type stubStore struct {
	deleteOlderThanCalls    int
	deleteExcessPerImgCalls int
	deleteCombinedCalls     int
	deleted                 int64
}

func (s *stubStore) DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error) {
	s.deleteOlderThanCalls++
	return s.deleted, nil
}

func (s *stubStore) DeleteExcessPerImage(ctx context.Context, keep int) (int64, error) {
	s.deleteExcessPerImgCalls++
	return s.deleted, nil
}

func (s *stubStore) DeleteExcessAndOld(ctx context.Context, age time.Duration, keep int) (int64, error) {
	s.deleteCombinedCalls++
	return s.deleted, nil
}

func TestCleanerStop_IsIdempotent(t *testing.T) {
	c := NewCleaner(CleanupConfig{Interval: time.Millisecond}, &stubStore{}, zerolog.Nop())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.Stop()
	}()
	go func() {
		defer wg.Done()
		c.Stop()
	}()
	wg.Wait()
}

func TestCleanerRun_BothPoliciesUsesCombinedPath(t *testing.T) {
	store := &stubStore{deleted: 1}
	c := NewCleaner(CleanupConfig{
		Interval:     time.Hour,
		MaxAge:       24 * time.Hour,
		KeepPerImage: 10,
	}, store, zerolog.Nop())

	c.run(context.Background())

	if store.deleteCombinedCalls != 1 {
		t.Fatalf("combined calls: want 1, got %d", store.deleteCombinedCalls)
	}
	if store.deleteOlderThanCalls != 0 {
		t.Fatalf("age calls: want 0, got %d", store.deleteOlderThanCalls)
	}
	if store.deleteExcessPerImgCalls != 0 {
		t.Fatalf("per-image calls: want 0, got %d", store.deleteExcessPerImgCalls)
	}
}
