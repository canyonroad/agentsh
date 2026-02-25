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
	assert.Equal(t, "local:blocklist.txt", result.FeedName, "adapter should redact directory path")
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
