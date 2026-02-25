package threatfeed

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyAdapter_RedactsLocalListPath(t *testing.T) {
	store := NewStore("", nil)
	store.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "local:/etc/agentsh/lists/blocklist.txt", AddedAt: time.Now()},
	})

	adapter := &PolicyAdapter{Store: store}
	result, matched := adapter.Check("evil.com")
	require.True(t, matched)
	assert.Equal(t, "local:blocklist.txt.1fb68369", result.FeedName, "adapter should redact directory path and append hash")
}

func TestPolicyAdapter_PreservesRemoteFeedName(t *testing.T) {
	store := NewStore("", nil)
	store.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})

	adapter := &PolicyAdapter{Store: store}
	result, matched := adapter.Check("evil.com")
	require.True(t, matched)
	assert.Equal(t, "urlhaus", result.FeedName, "remote feed names should not be modified")
}

func TestPolicyAdapter_NilStoreDoesNotPanic(t *testing.T) {
	adapter := &PolicyAdapter{Store: nil}
	_, matched := adapter.Check("evil.com")
	assert.False(t, matched, "nil store should return no match")
}

func TestPolicyAdapter_NilAdapterDoesNotPanic(t *testing.T) {
	var adapter *PolicyAdapter
	_, matched := adapter.Check("evil.com")
	assert.False(t, matched, "nil adapter should return no match")
}

func TestPolicyAdapter_SanitizesLocalBasename(t *testing.T) {
	store := NewStore("", nil)
	store.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "local:/tmp/my list (v2).txt", AddedAt: time.Now()},
	})

	adapter := &PolicyAdapter{Store: store}
	result, matched := adapter.Check("evil.com")
	require.True(t, matched)
	assert.Equal(t, "local:my_list__v2_.txt.2fbd3502", result.FeedName, "special chars in basename should be replaced with underscores and hash appended")
}
