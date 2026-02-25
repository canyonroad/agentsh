package threatfeed

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ExactMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	entry, matched := s.Check("evil.com")
	assert.True(t, matched)
	assert.Equal(t, "urlhaus", entry.FeedName)
}

func TestStore_NoMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("safe.com")
	assert.False(t, matched)
}

func TestStore_ParentDomainMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	entry, matched := s.Check("sub.evil.com")
	assert.True(t, matched)
	assert.Equal(t, "evil.com", entry.MatchedDomain)
}

func TestStore_DeepSubdomainMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	entry, matched := s.Check("a.b.c.evil.com")
	assert.True(t, matched)
	assert.Equal(t, "evil.com", entry.MatchedDomain)
}

func TestStore_AllowlistOverride(t *testing.T) {
	s := NewStore("", []string{"legit.evil.com"})
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("legit.evil.com")
	assert.False(t, matched, "allowlisted domain should not match")

	_, matched = s.Check("other.evil.com")
	assert.True(t, matched)
}

func TestStore_CaseInsensitive(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("EVIL.COM")
	assert.True(t, matched)
}

func TestStore_EmptyStore(t *testing.T) {
	s := NewStore("", nil)
	_, matched := s.Check("anything.com")
	assert.False(t, matched)
}

func TestStore_AtomicUpdate(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"old.com": {FeedName: "feed1", AddedAt: time.Now()},
	})
	s.Update(map[string]FeedEntry{
		"new.com": {FeedName: "feed2", AddedAt: time.Now()},
	})
	_, matched := s.Check("old.com")
	assert.False(t, matched, "old entries should be gone after update")
	_, matched = s.Check("new.com")
	assert.True(t, matched)
}

func TestStore_ConcurrentAccess(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.Check("evil.com")
		}()
		go func() {
			defer wg.Done()
			s.Update(map[string]FeedEntry{
				"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
			})
		}()
	}
	wg.Wait()
}

func TestStore_DiskRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1 := NewStore(dir, []string{"safe.com"})
	s1.Update(map[string]FeedEntry{
		"evil.com":    {FeedName: "urlhaus", AddedAt: time.Now()},
		"phishing.io": {FeedName: "phishdb", AddedAt: time.Now()},
	})
	err := s1.SaveToDisk()
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, "feeds.cache"))
	require.NoError(t, err)

	s2 := NewStore(dir, []string{"safe.com"})
	err = s2.LoadFromDisk()
	require.NoError(t, err)

	entry, matched := s2.Check("evil.com")
	assert.True(t, matched)
	assert.Equal(t, "urlhaus", entry.FeedName)

	entry, matched = s2.Check("phishing.io")
	assert.True(t, matched)
	assert.Equal(t, "phishdb", entry.FeedName)
}

func TestStore_LoadFromDisk_NoFile(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, nil)
	err := s.LoadFromDisk()
	assert.NoError(t, err, "missing cache file should not be an error")
}

func TestStore_Size(t *testing.T) {
	s := NewStore("", nil)
	assert.Equal(t, 0, s.Size())
	s.Update(map[string]FeedEntry{
		"a.com": {FeedName: "f1", AddedAt: time.Now()},
		"b.com": {FeedName: "f2", AddedAt: time.Now()},
	})
	assert.Equal(t, 2, s.Size())
}

func TestStore_AllowlistOverridesParentDomain(t *testing.T) {
	s := NewStore("", []string{"evil.com"})
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("sub.evil.com")
	assert.False(t, matched, "parent domain is allowlisted, child should not match")
}

func TestStore_TrailingDot(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("evil.com.")
	assert.True(t, matched, "trailing dot should be stripped")
}
