package secrets

import (
	"testing"
	"time"
)

func TestNewSecretCache(t *testing.T) {
	cache := newSecretCache(time.Minute)
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}
}

func TestSecretCache_SetGet(t *testing.T) {
	cache := newSecretCache(time.Minute)

	secret := &Secret{
		Path: "test/path",
		Data: map[string]string{"key": "value"},
	}

	cache.set("provider", "test/path", secret)

	got := cache.get("provider", "test/path")
	if got == nil {
		t.Fatal("expected to get cached secret")
	}

	if got.Path != secret.Path {
		t.Errorf("Path = %q, want %q", got.Path, secret.Path)
	}
}

func TestSecretCache_GetNotFound(t *testing.T) {
	cache := newSecretCache(time.Minute)

	got := cache.get("provider", "nonexistent")
	if got != nil {
		t.Error("expected nil for nonexistent key")
	}
}

func TestSecretCache_GetExpired(t *testing.T) {
	cache := newSecretCache(10 * time.Millisecond)

	secret := &Secret{
		Path: "test/path",
		Data: map[string]string{"key": "value"},
	}

	cache.set("provider", "test/path", secret)

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	got := cache.get("provider", "test/path")
	if got != nil {
		t.Error("expected nil for expired entry")
	}
}

func TestSecretCache_Delete(t *testing.T) {
	cache := newSecretCache(time.Minute)

	secret := &Secret{Path: "test/path"}
	cache.set("provider", "test/path", secret)

	cache.delete("provider", "test/path")

	got := cache.get("provider", "test/path")
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestSecretCache_Clear(t *testing.T) {
	cache := newSecretCache(time.Minute)

	cache.set("provider1", "path1", &Secret{Path: "path1"})
	cache.set("provider2", "path2", &Secret{Path: "path2"})

	cache.clear()

	if cache.size() != 0 {
		t.Errorf("size = %d, want 0", cache.size())
	}
}

func TestSecretCache_Size(t *testing.T) {
	cache := newSecretCache(time.Minute)

	if cache.size() != 0 {
		t.Errorf("initial size = %d, want 0", cache.size())
	}

	cache.set("provider1", "path1", &Secret{Path: "path1"})
	if cache.size() != 1 {
		t.Errorf("size = %d, want 1", cache.size())
	}

	cache.set("provider2", "path2", &Secret{Path: "path2"})
	if cache.size() != 2 {
		t.Errorf("size = %d, want 2", cache.size())
	}
}

func TestSecretCache_Key(t *testing.T) {
	cache := newSecretCache(time.Minute)

	key := cache.key("provider", "path")
	if key != "provider:path" {
		t.Errorf("key = %q, want provider:path", key)
	}
}

func TestSecretCache_Cleanup(t *testing.T) {
	cache := newSecretCache(10 * time.Millisecond)

	cache.set("provider", "path1", &Secret{Path: "path1"})
	cache.set("provider", "path2", &Secret{Path: "path2"})

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Manually trigger cleanup
	cache.cleanup()

	if cache.size() != 0 {
		t.Errorf("size after cleanup = %d, want 0", cache.size())
	}
}

func TestSecretCache_OverwriteExisting(t *testing.T) {
	cache := newSecretCache(time.Minute)

	cache.set("provider", "path", &Secret{Path: "path", Data: map[string]string{"key": "value1"}})
	cache.set("provider", "path", &Secret{Path: "path", Data: map[string]string{"key": "value2"}})

	got := cache.get("provider", "path")
	if got == nil {
		t.Fatal("expected to get cached secret")
	}

	v, _ := got.GetValue("key")
	if v != "value2" {
		t.Errorf("value = %q, want value2", v)
	}

	if cache.size() != 1 {
		t.Errorf("size = %d, want 1", cache.size())
	}
}

func TestSecretCache_DifferentProviders(t *testing.T) {
	cache := newSecretCache(time.Minute)

	cache.set("provider1", "path", &Secret{Path: "path", Data: map[string]string{"provider": "1"}})
	cache.set("provider2", "path", &Secret{Path: "path", Data: map[string]string{"provider": "2"}})

	got1 := cache.get("provider1", "path")
	got2 := cache.get("provider2", "path")

	if got1 == nil || got2 == nil {
		t.Fatal("expected both secrets to be cached")
	}

	v1, _ := got1.GetValue("provider")
	v2, _ := got2.GetValue("provider")

	if v1 != "1" || v2 != "2" {
		t.Errorf("values = %q, %q, want 1, 2", v1, v2)
	}

	if cache.size() != 2 {
		t.Errorf("size = %d, want 2", cache.size())
	}
}

func TestSecretCache_ConcurrentAccess(t *testing.T) {
	cache := newSecretCache(time.Minute)

	done := make(chan bool)

	// Writer
	go func() {
		for i := 0; i < 100; i++ {
			cache.set("provider", "path", &Secret{Path: "path"})
		}
		done <- true
	}()

	// Reader
	go func() {
		for i := 0; i < 100; i++ {
			cache.get("provider", "path")
		}
		done <- true
	}()

	// Deleter
	go func() {
		for i := 0; i < 100; i++ {
			cache.delete("provider", "path")
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done
}
