//go:build linux

package statemachine

import "sync"

// CacheValue is the value stored in a CacheView. The transition logic
// reads/writes this type; production wraps it around a preparedcache.Entry
// at the dispatcher boundary so the state-machine package stays decoupled
// from the cache implementation.
type CacheValue struct {
	Verb     string // RawVerb from effects.ClassifiedStatement
	GroupID  uint8  // primary effect group_id; used for re-evaluate at Execute
	OpaqueID string // optional: spine-test correlation
}

// CacheView is the subset of preparedcache.Cache that Transition consumes.
// Implementations must be safe for concurrent reads with one writer per
// connection (the per-conn goroutine).
type CacheView interface {
	Get(name string) (CacheValue, bool)
	Put(name string, v CacheValue)
	Delete(name string)
	Clear()
}

// FakeCacheView records every operation and is safe for unit tests. NOT
// for production.
type FakeCacheView struct {
	mu      sync.Mutex
	store   map[string]CacheValue
	history []CacheOp
}

// CacheOp records one observation against a FakeCacheView.
type CacheOp struct {
	Method string // "Get" | "Put" | "Delete" | "Clear"
	Key    string
	Value  CacheValue
	Hit    bool // only meaningful for "Get"
}

// NewFakeCacheView returns an empty fake.
func NewFakeCacheView() *FakeCacheView {
	return &FakeCacheView{store: map[string]CacheValue{}}
}

func (f *FakeCacheView) Get(name string) (CacheValue, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.store[name]
	f.history = append(f.history, CacheOp{Method: "Get", Key: name, Value: v, Hit: ok})
	return v, ok
}

func (f *FakeCacheView) Put(name string, v CacheValue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[name] = v
	f.history = append(f.history, CacheOp{Method: "Put", Key: name, Value: v})
}

func (f *FakeCacheView) Delete(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.store, name)
	f.history = append(f.history, CacheOp{Method: "Delete", Key: name})
}

func (f *FakeCacheView) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store = map[string]CacheValue{}
	f.history = append(f.history, CacheOp{Method: "Clear"})
}

// Recorded returns the operation history.
func (f *FakeCacheView) Recorded() []CacheOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]CacheOp, len(f.history))
	copy(out, f.history)
	return out
}
