//go:build linux

package preparedcache

import (
	"strconv"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestCache_PutGet_RoundTrip(t *testing.T) {
	c := New(4)
	c.Put("s1", Entry{Classification: effects.ClassifiedStatement{RawVerb: "SELECT"}})
	got, ok := c.Get("s1")
	if !ok {
		t.Fatal("Get miss; want hit")
	}
	if got.Classification.RawVerb != "SELECT" {
		t.Fatalf("RawVerb=%q want SELECT", got.Classification.RawVerb)
	}
}

func TestCache_Get_Miss(t *testing.T) {
	c := New(4)
	if _, ok := c.Get("nope"); ok {
		t.Fatal("hit on empty cache")
	}
}

func TestCache_Eviction_AtCap(t *testing.T) {
	c := New(2)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Put("b", Entry{Classification: effects.ClassifiedStatement{RawVerb: "B"}})
	c.Put("c", Entry{Classification: effects.ClassifiedStatement{RawVerb: "C"}})
	if _, ok := c.Get("a"); ok {
		t.Fatal("a not evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("b missing")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("c missing")
	}
}

func TestCache_Get_PromotesEntry(t *testing.T) {
	c := New(2)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Put("b", Entry{Classification: effects.ClassifiedStatement{RawVerb: "B"}})
	_, _ = c.Get("a") // promote a
	c.Put("c", Entry{Classification: effects.ClassifiedStatement{RawVerb: "C"}})
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should be retained")
	}
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should be evicted (was LRU)")
	}
}

func TestCache_Delete(t *testing.T) {
	c := New(4)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Delete("a")
	if _, ok := c.Get("a"); ok {
		t.Fatal("Get after Delete hit")
	}
	c.Delete("never-there") // no-op, no panic
}

func TestCache_Clear(t *testing.T) {
	c := New(4)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Put("b", Entry{Classification: effects.ClassifiedStatement{RawVerb: "B"}})
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len=%d want 0", c.Len())
	}
}

func TestCache_Concurrent(t *testing.T) {
	c := New(64)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				name := strconv.Itoa((w*1000 + i) % 32)
				c.Put(name, Entry{Classification: effects.ClassifiedStatement{RawVerb: name}})
				_, _ = c.Get(name)
				if i%37 == 0 {
					c.Delete(name)
				}
			}
		}(w)
	}
	wg.Wait()
	if c.Len() > 64 {
		t.Fatalf("Len=%d exceeded cap", c.Len())
	}
}
