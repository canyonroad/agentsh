package cache

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

func TestPutThenGet(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, DefaultTTL: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v := &skillcheck.Verdict{Action: skillcheck.VerdictWarn, Summary: "x"}
	c.Put("sha-abc", v)
	got, ok := c.Get("sha-abc")
	if !ok {
		t.Fatalf("expected cache hit")
	}
	if got.Action != skillcheck.VerdictWarn {
		t.Errorf("action=%s", got.Action)
	}
}

func TestExpiry(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, DefaultTTL: time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.Put("k", &skillcheck.Verdict{Action: skillcheck.VerdictAllow})
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Errorf("expected miss after TTL")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, DefaultTTL: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.Put("k", &skillcheck.Verdict{Action: skillcheck.VerdictBlock})
	if err := c.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	c2, err := New(Config{Dir: dir, DefaultTTL: time.Hour})
	if err != nil {
		t.Fatalf("New2: %v", err)
	}
	got, ok := c2.Get("k")
	if !ok || got.Action != skillcheck.VerdictBlock {
		t.Errorf("persistence failed; ok=%v action=%s", ok, got.Action)
	}
}
