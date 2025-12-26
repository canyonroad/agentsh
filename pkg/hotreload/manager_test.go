package hotreload

import (
	"context"
	"testing"
)

func TestReloadable(t *testing.T) {
	initial := "initial"
	r := NewReloadable(&initial)

	t.Run("Get", func(t *testing.T) {
		got := r.Get()
		if got == nil || *got != "initial" {
			t.Errorf("Get() = %v, want initial", got)
		}
	})

	t.Run("Swap", func(t *testing.T) {
		newValue := "updated"
		old := r.Swap(&newValue)

		if old == nil || *old != "initial" {
			t.Errorf("Swap() returned %v, want initial", old)
		}

		got := r.Get()
		if got == nil || *got != "updated" {
			t.Errorf("Get() after Swap = %v, want updated", got)
		}
	})

	t.Run("Version", func(t *testing.T) {
		v := r.Version()
		if v != 1 {
			t.Errorf("Version() = %d, want 1 (after one swap)", v)
		}

		another := "another"
		r.Swap(&another)

		v = r.Version()
		if v != 2 {
			t.Errorf("Version() = %d, want 2 (after two swaps)", v)
		}
	})

	t.Run("CompareAndSwap", func(t *testing.T) {
		current := r.Get()
		wrong := "wrong"
		correct := "correct"

		// Should fail with wrong old value
		if r.CompareAndSwap(&wrong, &correct) {
			t.Error("CompareAndSwap should fail with wrong old value")
		}

		// Should succeed with correct old value
		if !r.CompareAndSwap(current, &correct) {
			t.Error("CompareAndSwap should succeed with correct old value")
		}

		got := r.Get()
		if got == nil || *got != "correct" {
			t.Errorf("Get() after CAS = %v, want correct", got)
		}
	})
}

func TestReloadable_Nil(t *testing.T) {
	r := NewReloadable[string](nil)

	got := r.Get()
	if got != nil {
		t.Errorf("Get() on nil = %v, want nil", got)
	}

	value := "value"
	r.Swap(&value)

	got = r.Get()
	if got == nil || *got != "value" {
		t.Errorf("Get() after Swap = %v, want value", got)
	}
}

func TestNewConfigManager(t *testing.T) {
	manager := NewConfigManager()
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestConfigManager_Start(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher error: %v", err)
	}

	manager := NewConfigManager(
		WithPolicyWatcher(watcher),
		WithRuntimeConfig(NewRuntimeConfig()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := manager.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer manager.Stop()

	// Starting again should error
	if err := manager.Start(ctx); err == nil {
		t.Error("expected error starting twice")
	}
}

func TestConfigManager_Stop(t *testing.T) {
	manager := NewConfigManager()

	// Stopping when not started should be fine
	if err := manager.Stop(); err != nil {
		t.Errorf("Stop error: %v", err)
	}

	ctx := context.Background()
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	if err := manager.Stop(); err != nil {
		t.Errorf("Stop error: %v", err)
	}

	// Stopping again should be fine
	if err := manager.Stop(); err != nil {
		t.Errorf("Stop again error: %v", err)
	}
}

func TestConfigManager_PolicyWatcher(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	watcher, _ := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})

	manager := NewConfigManager(WithPolicyWatcher(watcher))

	if manager.PolicyWatcher() != watcher {
		t.Error("PolicyWatcher() should return the configured watcher")
	}
}

func TestConfigManager_Runtime(t *testing.T) {
	runtime := NewRuntimeConfig()
	manager := NewConfigManager(WithRuntimeConfig(runtime))

	if manager.Runtime() != runtime {
		t.Error("Runtime() should return the configured runtime")
	}
}

func TestConfigManager_Register(t *testing.T) {
	manager := NewConfigManager()

	value := "test"
	r := NewReloadable(&value)
	manager.Register("test", r)

	got, ok := manager.Get("test")
	if !ok {
		t.Error("Get(test) should return true")
	}

	if got != r {
		t.Error("Get(test) should return the registered value")
	}

	_, ok = manager.Get("missing")
	if ok {
		t.Error("Get(missing) should return false")
	}
}

func TestConfigManager_TriggerReload(t *testing.T) {
	manager := NewConfigManager()

	// Should be fine without watcher
	if err := manager.TriggerReload(); err != nil {
		t.Errorf("TriggerReload error: %v", err)
	}
}

func TestConfigManager_Status(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	watcher, _ := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})

	runtime := NewRuntimeConfig()
	runtime.SetLogLevel("debug")

	manager := NewConfigManager(
		WithPolicyWatcher(watcher),
		WithRuntimeConfig(runtime),
	)

	status := manager.Status()

	if status.Running {
		t.Error("Running should be false before Start")
	}

	if status.WatcherStats == nil {
		t.Error("WatcherStats should not be nil")
	}

	if status.RuntimeConfig == nil {
		t.Error("RuntimeConfig should not be nil")
	}

	if status.RuntimeConfig.LogLevel != "debug" {
		t.Errorf("RuntimeConfig.LogLevel = %q, want debug", status.RuntimeConfig.LogLevel)
	}

	// Start and check again
	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop()

	status = manager.Status()
	if !status.Running {
		t.Error("Running should be true after Start")
	}
}
