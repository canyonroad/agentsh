package events

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNopSink_EmitNeverFails(t *testing.T) {
	s := NopSink{}
	if err := s.EmitStatement(context.Background(), DBEvent{}); err != nil {
		t.Fatalf("EmitStatement: %v", err)
	}
	if err := s.EmitLifecycle(context.Background(), LifecycleEvent{}); err != nil {
		t.Fatalf("EmitLifecycle: %v", err)
	}
}

func TestSyncSink_DrainReturnsEventsInOrder(t *testing.T) {
	s := &SyncSink{}
	for i := 0; i < 3; i++ {
		if err := s.EmitStatement(context.Background(), DBEvent{EventID: string(rune('A' + i))}); err != nil {
			t.Fatalf("EmitStatement: %v", err)
		}
	}
	if err := s.EmitLifecycle(context.Background(), LifecycleEvent{Kind: "db_listener_auth_fail"}); err != nil {
		t.Fatalf("EmitLifecycle: %v", err)
	}
	stmts := s.DrainStatements()
	if len(stmts) != 3 || stmts[0].EventID != "A" || stmts[2].EventID != "C" {
		t.Fatalf("DrainStatements = %+v", stmts)
	}
	if got := s.DrainStatements(); len(got) != 0 {
		t.Fatalf("DrainStatements after drain = %+v, want empty", got)
	}
	lcs := s.DrainLifecycle()
	if len(lcs) != 1 || lcs[0].Kind != "db_listener_auth_fail" {
		t.Fatalf("DrainLifecycle = %+v", lcs)
	}
}

func TestSyncSink_ConcurrentEmitIsSafe(t *testing.T) {
	s := &SyncSink{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.EmitStatement(context.Background(), DBEvent{Timestamp: time.Now()})
		}()
	}
	wg.Wait()
	if got := len(s.DrainStatements()); got != 100 {
		t.Fatalf("DrainStatements len = %d, want 100", got)
	}
}

func TestSyncSink_ConcurrentLifecycleEmitIsSafe(t *testing.T) {
	s := &SyncSink{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.EmitLifecycle(context.Background(), LifecycleEvent{Timestamp: time.Now(), Kind: "db_listener_auth_fail"})
		}()
	}
	wg.Wait()
	if got := len(s.DrainLifecycle()); got != 100 {
		t.Fatalf("DrainLifecycle len = %d, want 100", got)
	}
}

func TestSyncSink_ContextCancelled_ReturnsError(t *testing.T) {
	s := &SyncSink{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.EmitStatement(ctx, DBEvent{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("EmitStatement err = %v, want context.Canceled", err)
	}
}
