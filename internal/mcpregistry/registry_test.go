package mcpregistry

import (
	"fmt"
	"sync"
	"testing"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.tools == nil {
		t.Fatal("tools map not initialized")
	}
	if r.addrs == nil {
		t.Fatal("addrs map not initialized")
	}
}

func TestRegisterAndLookup(t *testing.T) {
	r := NewRegistry()

	tools := []ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
		{Name: "list_files", Hash: "def456"},
	}
	r.Register("server-1", "stdio", "", tools)

	entry := r.Lookup("get_weather")
	if entry == nil {
		t.Fatal("Lookup returned nil for registered tool")
	}
	if entry.ToolName != "get_weather" {
		t.Errorf("ToolName = %q, want %q", entry.ToolName, "get_weather")
	}
	if entry.ServerID != "server-1" {
		t.Errorf("ServerID = %q, want %q", entry.ServerID, "server-1")
	}
	if entry.ServerType != "stdio" {
		t.Errorf("ServerType = %q, want %q", entry.ServerType, "stdio")
	}
	if entry.ServerAddr != "" {
		t.Errorf("ServerAddr = %q, want empty string", entry.ServerAddr)
	}
	if entry.ToolHash != "abc123" {
		t.Errorf("ToolHash = %q, want %q", entry.ToolHash, "abc123")
	}
	if entry.RegisteredAt.IsZero() {
		t.Error("RegisteredAt is zero")
	}

	entry2 := r.Lookup("list_files")
	if entry2 == nil {
		t.Fatal("Lookup returned nil for second registered tool")
	}
	if entry2.ToolHash != "def456" {
		t.Errorf("ToolHash = %q, want %q", entry2.ToolHash, "def456")
	}
}

func TestLookupUnknownTool(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "known_tool", Hash: "h1"},
	})

	entry := r.Lookup("unknown_tool")
	if entry != nil {
		t.Errorf("Lookup for unknown tool returned %+v, want nil", entry)
	}
}

func TestLookupEmptyRegistry(t *testing.T) {
	r := NewRegistry()

	entry := r.Lookup("anything")
	if entry != nil {
		t.Errorf("Lookup on empty registry returned %+v, want nil", entry)
	}
}

func TestRegisterEmptyTools(t *testing.T) {
	r := NewRegistry()

	// No tools, no addr — no entries at all.
	r.Register("server-1", "stdio", "", nil)

	if len(r.tools) != 0 {
		t.Errorf("tools map has %d entries, want 0", len(r.tools))
	}
	if len(r.addrs) != 0 {
		t.Errorf("addrs map has %d entries, want 0", len(r.addrs))
	}

	// No tools but has addr — addr should still be recorded.
	r.Register("server-2", "http", "host:8080", []ToolInfo{})

	if len(r.tools) != 0 {
		t.Errorf("tools map has %d entries, want 0", len(r.tools))
	}
	if len(r.addrs) != 1 {
		t.Errorf("addrs map has %d entries, want 1 (addr should be recorded even with empty tools)", len(r.addrs))
	}
	if r.addrs["host:8080"] != "server-2" {
		t.Errorf("addrs[host:8080] = %q, want %q", r.addrs["host:8080"], "server-2")
	}
}

func TestDuplicateToolNameLastWriteWins(t *testing.T) {
	r := NewRegistry()

	// First server registers "get_weather".
	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})

	// Second server also registers "get_weather" — should overwrite.
	overwrites := r.Register("server-2", "http", "weather.example.com:443", []ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	if len(overwrites) != 1 {
		t.Fatalf("expected 1 overwrite, got %d", len(overwrites))
	}
	if overwrites[0].ToolName != "get_weather" {
		t.Errorf("overwrite ToolName = %q, want %q", overwrites[0].ToolName, "get_weather")
	}
	if overwrites[0].PreviousServerID != "server-1" {
		t.Errorf("overwrite PreviousServerID = %q, want %q", overwrites[0].PreviousServerID, "server-1")
	}
	if overwrites[0].NewServerID != "server-2" {
		t.Errorf("overwrite NewServerID = %q, want %q", overwrites[0].NewServerID, "server-2")
	}

	entry := r.Lookup("get_weather")
	if entry == nil {
		t.Fatal("Lookup returned nil")
	}
	if entry.ServerID != "server-2" {
		t.Errorf("ServerID = %q, want %q (last-write-wins)", entry.ServerID, "server-2")
	}
	if entry.ToolHash != "hash-v2" {
		t.Errorf("ToolHash = %q, want %q", entry.ToolHash, "hash-v2")
	}
	if entry.ServerType != "http" {
		t.Errorf("ServerType = %q, want %q", entry.ServerType, "http")
	}
	if entry.ServerAddr != "weather.example.com:443" {
		t.Errorf("ServerAddr = %q, want %q", entry.ServerAddr, "weather.example.com:443")
	}
}

func TestLookupBatch(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
		{Name: "tool_b", Hash: "hb"},
	})
	r.Register("server-2", "http", "host:80", []ToolInfo{
		{Name: "tool_c", Hash: "hc"},
	})

	result := r.LookupBatch([]string{"tool_a", "tool_c", "tool_missing"})

	if len(result) != 2 {
		t.Fatalf("LookupBatch returned %d entries, want 2", len(result))
	}
	if result["tool_a"] == nil {
		t.Error("tool_a missing from batch result")
	}
	if result["tool_c"] == nil {
		t.Error("tool_c missing from batch result")
	}
	if _, ok := result["tool_missing"]; ok {
		t.Error("tool_missing should not be in batch result")
	}
}

func TestLookupBatchEmpty(t *testing.T) {
	r := NewRegistry()
	r.Register("s1", "stdio", "", []ToolInfo{{Name: "t1", Hash: "h1"}})

	result := r.LookupBatch(nil)
	if len(result) != 0 {
		t.Errorf("LookupBatch(nil) returned %d entries, want 0", len(result))
	}

	result = r.LookupBatch([]string{})
	if len(result) != 0 {
		t.Errorf("LookupBatch([]) returned %d entries, want 0", len(result))
	}
}

func TestServerAddrsOnlyNetwork(t *testing.T) {
	r := NewRegistry()

	// Stdio server: empty addr should NOT appear in ServerAddrs.
	r.Register("stdio-server", "stdio", "", []ToolInfo{
		{Name: "stdio_tool", Hash: "h1"},
	})

	// Network server: non-empty addr should appear.
	r.Register("http-server", "http", "mcp.example.com:443", []ToolInfo{
		{Name: "http_tool", Hash: "h2"},
	})

	// SSE server: also network, should appear.
	r.Register("sse-server", "sse", "sse.example.com:8080", []ToolInfo{
		{Name: "sse_tool", Hash: "h3"},
	})

	addrs := r.ServerAddrs()
	if len(addrs) != 2 {
		t.Fatalf("ServerAddrs returned %d entries, want 2", len(addrs))
	}
	if addrs["mcp.example.com:443"] != "http-server" {
		t.Errorf("addrs[mcp.example.com:443] = %q, want %q", addrs["mcp.example.com:443"], "http-server")
	}
	if addrs["sse.example.com:8080"] != "sse-server" {
		t.Errorf("addrs[sse.example.com:8080] = %q, want %q", addrs["sse.example.com:8080"], "sse-server")
	}
}

func TestServerAddrsReturnsCopy(t *testing.T) {
	r := NewRegistry()

	r.Register("s1", "http", "host:80", []ToolInfo{
		{Name: "t1", Hash: "h1"},
	})

	addrs := r.ServerAddrs()
	addrs["mutated"] = "bad" // mutate the returned map

	// Original should be unaffected.
	addrsAgain := r.ServerAddrs()
	if _, ok := addrsAgain["mutated"]; ok {
		t.Error("ServerAddrs did not return a copy; mutation leaked back")
	}
}

func TestServerAddrsEmpty(t *testing.T) {
	r := NewRegistry()

	addrs := r.ServerAddrs()
	if addrs == nil {
		t.Fatal("ServerAddrs on empty registry returned nil, want empty map")
	}
	if len(addrs) != 0 {
		t.Errorf("ServerAddrs returned %d entries, want 0", len(addrs))
	}
}

func TestRemove(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
		{Name: "tool_b", Hash: "hb"},
	})
	r.Register("server-2", "http", "host:443", []ToolInfo{
		{Name: "tool_c", Hash: "hc"},
	})

	// Verify tools exist before removal.
	if r.Lookup("tool_a") == nil {
		t.Fatal("tool_a should exist before Remove")
	}
	if r.Lookup("tool_c") == nil {
		t.Fatal("tool_c should exist before Remove")
	}

	// Remove server-1.
	r.Remove("server-1")

	if entry := r.Lookup("tool_a"); entry != nil {
		t.Errorf("tool_a should be nil after removing server-1, got %+v", entry)
	}
	if entry := r.Lookup("tool_b"); entry != nil {
		t.Errorf("tool_b should be nil after removing server-1, got %+v", entry)
	}

	// server-2's tool should still exist.
	if entry := r.Lookup("tool_c"); entry == nil {
		t.Error("tool_c should still exist after removing server-1")
	}

	// server-2's address should still be in the address map.
	addrs := r.ServerAddrs()
	if addrs["host:443"] != "server-2" {
		t.Errorf("server-2 addr should still be present, got %v", addrs)
	}
}

func TestRemoveNetworkServer(t *testing.T) {
	r := NewRegistry()

	r.Register("net-server", "http", "mcp.host:8080", []ToolInfo{
		{Name: "net_tool", Hash: "h1"},
	})

	addrs := r.ServerAddrs()
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr before remove, got %d", len(addrs))
	}

	r.Remove("net-server")

	if entry := r.Lookup("net_tool"); entry != nil {
		t.Error("net_tool should be nil after removing net-server")
	}
	addrs = r.ServerAddrs()
	if len(addrs) != 0 {
		t.Errorf("expected 0 addrs after remove, got %d", len(addrs))
	}
}

func TestRemoveNonexistentServer(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
	})

	// Removing a server that doesn't exist should be a no-op.
	r.Remove("nonexistent")

	if entry := r.Lookup("tool_a"); entry == nil {
		t.Error("tool_a should still exist after removing nonexistent server")
	}
}

func TestConcurrentAccess(t *testing.T) {
	r := NewRegistry()

	const (
		numWriters = 10
		numReaders = 20
		numTools   = 50
	)

	var wg sync.WaitGroup

	// Spawn writers: each registers tools under its own server.
	for w := range numWriters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serverID := fmt.Sprintf("server-%d", w)
			tools := make([]ToolInfo, numTools)
			for i := range numTools {
				tools[i] = ToolInfo{
					Name: fmt.Sprintf("tool_%d_%d", w, i),
					Hash: fmt.Sprintf("hash_%d_%d", w, i),
				}
			}
			r.Register(serverID, "stdio", "", tools)
		}()
	}

	// Spawn readers: each does Lookup and LookupBatch concurrently.
	for range numReaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				r.Lookup("tool_0_0")
				r.LookupBatch([]string{"tool_1_0", "tool_2_0", "nonexistent"})
				r.ServerAddrs()
			}
		}()
	}

	// Also do concurrent removes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			r.Remove("server-999") // nonexistent, but exercises the lock path
		}
	}()

	wg.Wait()

	// After all writers complete, verify each writer's tools are present.
	for w := range numWriters {
		for i := range numTools {
			toolName := fmt.Sprintf("tool_%d_%d", w, i)
			entry := r.Lookup(toolName)
			if entry == nil {
				t.Errorf("tool %q not found after concurrent writes", toolName)
				return // avoid flooding
			}
		}
	}
}

func TestConcurrentRegisterAndRemove(t *testing.T) {
	r := NewRegistry()

	var wg sync.WaitGroup

	// Writer goroutine registers tools for server-1.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 100 {
			r.Register("server-1", "http", "host:80", []ToolInfo{
				{Name: fmt.Sprintf("tool_%d", i), Hash: "h"},
			})
		}
	}()

	// Remover goroutine removes server-1 concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			r.Remove("server-1")
		}
	}()

	// Reader goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			r.Lookup("tool_50")
			r.ServerAddrs()
		}
	}()

	// Should not panic or deadlock.
	wg.Wait()
}

func TestMultipleNetworkServersShareNoAddr(t *testing.T) {
	r := NewRegistry()

	// Two stdio servers: neither should add to addrs.
	r.Register("stdio-1", "stdio", "", []ToolInfo{{Name: "t1", Hash: "h1"}})
	r.Register("stdio-2", "stdio", "", []ToolInfo{{Name: "t2", Hash: "h2"}})

	addrs := r.ServerAddrs()
	if len(addrs) != 0 {
		t.Errorf("expected 0 addrs for stdio-only servers, got %d", len(addrs))
	}
}

func TestRegisterSameAddrDifferentServers(t *testing.T) {
	r := NewRegistry()

	// Two servers at the same address: last one wins in the addrs map.
	r.Register("server-a", "http", "shared-host:443", []ToolInfo{{Name: "ta", Hash: "ha"}})
	r.Register("server-b", "http", "shared-host:443", []ToolInfo{{Name: "tb", Hash: "hb"}})

	addrs := r.ServerAddrs()
	if addrs["shared-host:443"] != "server-b" {
		t.Errorf("addr should map to server-b (last write), got %q", addrs["shared-host:443"])
	}
}

func TestRegisterPreservesOtherServerTools(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "exclusive_tool", Hash: "h1"},
	})

	// Registering tools for a different server should not affect server-1's tools.
	r.Register("server-2", "http", "host:80", []ToolInfo{
		{Name: "other_tool", Hash: "h2"},
	})

	entry := r.Lookup("exclusive_tool")
	if entry == nil {
		t.Fatal("exclusive_tool should still exist")
	}
	if entry.ServerID != "server-1" {
		t.Errorf("exclusive_tool ServerID = %q, want %q", entry.ServerID, "server-1")
	}
}

func TestRegisteredAtTimestamp(t *testing.T) {
	r := NewRegistry()

	r.Register("s1", "stdio", "", []ToolInfo{
		{Name: "tool_1", Hash: "h1"},
		{Name: "tool_2", Hash: "h2"},
	})

	e1 := r.Lookup("tool_1")
	e2 := r.Lookup("tool_2")

	if e1 == nil || e2 == nil {
		t.Fatal("both tools should be found")
	}

	// Tools registered in the same Register call should share the same timestamp.
	if !e1.RegisteredAt.Equal(e2.RegisteredAt) {
		t.Errorf("tools in same batch have different timestamps: %v vs %v",
			e1.RegisteredAt, e2.RegisteredAt)
	}
}

func TestLookupReturnsCopy(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "original"},
	})

	entry := r.Lookup("tool_a")
	if entry == nil {
		t.Fatal("Lookup returned nil")
	}

	// Mutate the returned copy.
	entry.ToolHash = "mutated"
	entry.ServerID = "hacked"

	// Internal state should be unaffected.
	entry2 := r.Lookup("tool_a")
	if entry2.ToolHash != "original" {
		t.Errorf("Lookup did not return a copy; mutation leaked: ToolHash = %q", entry2.ToolHash)
	}
	if entry2.ServerID != "server-1" {
		t.Errorf("Lookup did not return a copy; mutation leaked: ServerID = %q", entry2.ServerID)
	}
}

func TestLookupBatchReturnsCopies(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
	})

	batch := r.LookupBatch([]string{"tool_a"})
	if batch["tool_a"] == nil {
		t.Fatal("tool_a missing from batch")
	}

	// Mutate the returned copy.
	batch["tool_a"].ToolHash = "mutated"

	// Internal state should be unaffected.
	entry := r.Lookup("tool_a")
	if entry.ToolHash != "ha" {
		t.Errorf("LookupBatch did not return copies; mutation leaked: ToolHash = %q", entry.ToolHash)
	}
}

func TestRegisterSameServerNoOverwrite(t *testing.T) {
	r := NewRegistry()

	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "v1"},
	})

	// Same server re-registering the same tool should NOT be reported as overwrite.
	overwrites := r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "v2"},
	})

	if len(overwrites) != 0 {
		t.Errorf("expected 0 overwrites for same server, got %d", len(overwrites))
	}
}

func TestCallbackOnMultiServerFiresOnSecondServer(t *testing.T) {
	r := NewRegistry()

	var calls int
	r.SetCallbacks(RegistryCallbacks{
		OnMultiServer: func() { calls++ },
	})

	// Register first server — OnMultiServer should NOT fire.
	r.Register("server-a", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
	})
	if calls != 0 {
		t.Fatalf("OnMultiServer called after 1st server, got %d calls", calls)
	}

	// Register second server — OnMultiServer should fire exactly once.
	r.Register("server-b", "stdio", "", []ToolInfo{
		{Name: "tool_b", Hash: "hb"},
	})
	if calls != 1 {
		t.Fatalf("OnMultiServer not called after 2nd server, got %d calls", calls)
	}
}

func TestCallbackOnMultiServerNotFiredOnFirstServer(t *testing.T) {
	r := NewRegistry()

	var calls int
	r.SetCallbacks(RegistryCallbacks{
		OnMultiServer: func() { calls++ },
	})

	r.Register("server-a", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
	})

	if calls != 0 {
		t.Errorf("OnMultiServer should not fire for first server, got %d calls", calls)
	}
}

func TestCallbackOnMultiServerFiredOnlyOnce(t *testing.T) {
	r := NewRegistry()

	var calls int
	r.SetCallbacks(RegistryCallbacks{
		OnMultiServer: func() { calls++ },
	})

	r.Register("server-a", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
	})
	r.Register("server-b", "stdio", "", []ToolInfo{
		{Name: "tool_b", Hash: "hb"},
	})
	r.Register("server-c", "stdio", "", []ToolInfo{
		{Name: "tool_c", Hash: "hc"},
	})

	if calls != 1 {
		t.Errorf("OnMultiServer should fire exactly once, got %d calls", calls)
	}
}

func TestCallbackOnOverwriteFiresOnCollision(t *testing.T) {
	r := NewRegistry()

	type overwriteRecord struct {
		toolName    string
		oldServerID string
		newServerID string
	}
	var records []overwriteRecord

	r.SetCallbacks(RegistryCallbacks{
		OnOverwrite: func(toolName, oldServerID, newServerID string) {
			records = append(records, overwriteRecord{toolName, oldServerID, newServerID})
		},
	})

	// Register "foo" from server-a.
	r.Register("server-a", "stdio", "", []ToolInfo{
		{Name: "foo", Hash: "h1"},
	})
	if len(records) != 0 {
		t.Fatalf("OnOverwrite should not fire on first registration, got %d calls", len(records))
	}

	// Register "foo" from server-b — collision.
	r.Register("server-b", "stdio", "", []ToolInfo{
		{Name: "foo", Hash: "h2"},
	})
	if len(records) != 1 {
		t.Fatalf("expected 1 OnOverwrite call, got %d", len(records))
	}
	if records[0].toolName != "foo" {
		t.Errorf("OnOverwrite toolName = %q, want %q", records[0].toolName, "foo")
	}
	if records[0].oldServerID != "server-a" {
		t.Errorf("OnOverwrite oldServerID = %q, want %q", records[0].oldServerID, "server-a")
	}
	if records[0].newServerID != "server-b" {
		t.Errorf("OnOverwrite newServerID = %q, want %q", records[0].newServerID, "server-b")
	}
}

func TestNoCallbacksSetNoPanic(t *testing.T) {
	r := NewRegistry()

	// Register without setting callbacks — should not panic.
	r.Register("server-a", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "ha"},
	})
	r.Register("server-b", "stdio", "", []ToolInfo{
		{Name: "tool_a", Hash: "hb"}, // collision
	})
	r.Register("server-c", "http", "host:80", []ToolInfo{
		{Name: "tool_c", Hash: "hc"},
	})
	// If we reach here without panic, the test passes.
}
