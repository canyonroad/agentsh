# Staged Policy Validation & Promotion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `.staging/` directory support to `PolicyWatcher` so policies dropped there are validated (including signature verification based on config), then atomically moved to the live policy directory to trigger a reload.

**Architecture:** Extend the existing `PolicyWatcher` in `pkg/hotreload/watcher.go`. Staging events are detected by checking if the fsnotify path is under `<policyDir>/.staging/`. Both `.yaml` and `.sig` file writes reset a staging debounce timer (keyed by policy base name). After debounce, `Validate` is called on the staged file (which already does signature checking via the `PolicyLoader` interface). On success, files are moved to the live directory (`.sig` first, then `.yaml`) where the existing fsnotify reload picks them up.

**Tech Stack:** Go stdlib (`os`, `path/filepath`), `fsnotify`, existing `PolicyLoader` interface, existing `signing` package (consumed indirectly via `Validate`).

**Reference:** Design spec at `docs/superpowers/specs/2026-03-18-policy-signing-design.md` lines 189-201.

**Design note — signing metadata logging:** The spec requires logging `key_id`, `signer`, `signed_at` on successful staging promotion. The watcher delegates validation to `PolicyLoader.Validate()`, which is implemented in `internal/api` and already has access to the signing config and trust store. Signing metadata logging happens inside that `Validate` implementation, not in the watcher. The watcher is in `pkg/` and must not import `internal/` packages.

**Design note — `.staging/` must be on the same filesystem** as the policy directory, since promotion uses `os.Rename` (atomic on same filesystem). This is guaranteed when `.staging/` is a subdirectory of the policy dir.

---

### Task 1: Add staging helper functions and config

**Files:**
- Modify: `pkg/hotreload/watcher.go`
- Test: `pkg/hotreload/watcher_test.go`

- [ ] **Step 1: Write failing tests for staging helpers**

```go
func TestIsInStagingDir(t *testing.T) {
	tests := []struct {
		path      string
		policyDir string
		want      bool
	}{
		{"/etc/agentsh/policies/.staging/foo.yaml", "/etc/agentsh/policies", true},
		{"/etc/agentsh/policies/.staging/foo.yaml.sig", "/etc/agentsh/policies", true},
		{"/etc/agentsh/policies/foo.yaml", "/etc/agentsh/policies", false},
		{"/etc/agentsh/policies/subdir/foo.yaml", "/etc/agentsh/policies", false},
		{"/other/.staging/foo.yaml", "/etc/agentsh/policies", false},
	}
	for _, tt := range tests {
		if got := isInStagingDir(tt.path, tt.policyDir); got != tt.want {
			t.Errorf("isInStagingDir(%q, %q) = %v, want %v", tt.path, tt.policyDir, got, tt.want)
		}
	}
}

func TestIsStagingRelevant(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"foo.yaml", true},
		{"foo.yml", true},
		{"foo.json", true},
		{"foo.yaml.sig", true},
		{"foo.yml.sig", true},
		{"foo.json.sig", true},
		{"foo.txt", false},
		{"foo.sig", false}, // bare .sig without policy extension
	}
	for _, tt := range tests {
		if got := isStagingRelevant(tt.path); got != tt.want {
			t.Errorf("isStagingRelevant(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestStagingPolicyPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/staging/foo.yaml", "/staging/foo.yaml"},
		{"/staging/foo.yaml.sig", "/staging/foo.yaml"},
		{"/staging/foo.yml.sig", "/staging/foo.yml"},
	}
	for _, tt := range tests {
		if got := stagingPolicyPath(tt.path); got != tt.want {
			t.Errorf("stagingPolicyPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/hotreload/ -run "TestIsInStagingDir|TestIsStagingRelevant|TestStagingPolicyPath" -v`
Expected: FAIL — functions not defined

- [ ] **Step 3: Implement helpers and config**

Add to `watcher.go`:

```go
const stagingDirName = ".staging"

// isInStagingDir reports whether path is inside the .staging subdirectory of policyDir.
func isInStagingDir(path, policyDir string) bool {
	stagingPrefix := filepath.Join(policyDir, stagingDirName) + string(filepath.Separator)
	return strings.HasPrefix(path, stagingPrefix)
}

// isStagingRelevant reports whether a file in .staging/ should trigger staging processing.
// Matches policy files (.yaml, .yml, .json) and their companion .sig files.
func isStagingRelevant(path string) bool {
	if isPolicyFile(path) {
		return true
	}
	// Check for .sig companion: strip .sig and check if remainder is a policy file
	if strings.HasSuffix(path, ".sig") {
		return isPolicyFile(strings.TrimSuffix(path, ".sig"))
	}
	return false
}

// stagingPolicyPath returns the policy file path for a staging event.
// If path ends in .sig, strips the .sig suffix to get the policy path.
func stagingPolicyPath(path string) string {
	if strings.HasSuffix(path, ".sig") {
		base := strings.TrimSuffix(path, ".sig")
		if isPolicyFile(base) {
			return base
		}
	}
	return path
}
```

Add `strings` to the import block. Add `StagingDebounce` to `WatcherConfig`:

```go
type WatcherConfig struct {
	PolicyDir       string
	Loader          PolicyLoader
	Debounce        time.Duration // Debounce period for live policy changes
	StagingDebounce time.Duration // Debounce for staging (longer, to allow .sig to arrive)
	OnChange        func(path string, err error)
	OnStaging       func(path string, err error) // Called after staging validation attempt
}
```

In `NewPolicyWatcher`, set the staging debounce default:

```go
stagingDebounce := config.StagingDebounce
if stagingDebounce == 0 {
	stagingDebounce = 2 * time.Second
}
```

Add `stagingDebounce`, `stagingChan`, and `onStaging` fields to `PolicyWatcher`:

```go
type PolicyWatcher struct {
	policyDir       string
	loader          PolicyLoader
	watcher         *fsnotify.Watcher
	debounce        time.Duration
	stagingDebounce time.Duration
	onChange         func(path string, err error)
	onStaging        func(path string, err error)
	mu              sync.RWMutex
	running         atomic.Bool
	reloadChan      chan string
	stagingChan     chan string
	stats           WatcherStats
}
```

Initialize `stagingChan` in `NewPolicyWatcher`:

```go
return &PolicyWatcher{
	policyDir:       config.PolicyDir,
	loader:          config.Loader,
	debounce:        debounce,
	stagingDebounce: stagingDebounce,
	onChange:        config.OnChange,
	onStaging:       config.OnStaging,
	reloadChan:      make(chan string, 100),
	stagingChan:     make(chan string, 100),
}, nil
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/hotreload/ -run "TestIsInStagingDir|TestIsStagingRelevant|TestStagingPolicyPath" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/hotreload/watcher.go pkg/hotreload/watcher_test.go
git commit -m "feat(hotreload): add staging helper functions and config"
```

---

### Task 2: Route staging events in processEvents

**Files:**
- Modify: `pkg/hotreload/watcher.go`
- Test: `pkg/hotreload/watcher_test.go`

- [ ] **Step 1: Write failing test — staging file does NOT trigger live reload**

```go
func TestPolicyWatcher_StagingFileDoesNotTriggerLiveReload(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}
	changed := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 50 * time.Millisecond,
		OnChange: func(path string, err error) {
			select {
			case changed <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write a policy file to .staging/ — should NOT trigger onChange
	os.WriteFile(filepath.Join(stagingDir, "test.yaml"), []byte("test: true"), 0644)

	select {
	case <-changed:
		t.Error("staging file should not trigger live reload onChange")
	case <-time.After(300 * time.Millisecond):
		// Expected: no change event
	}

	if loader.LoadCount() != 0 {
		t.Error("loader should not be called for staging files")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/hotreload/ -run TestPolicyWatcher_StagingFileDoesNotTriggerLiveReload -v`
Expected: FAIL — staging file currently triggers live reload

- [ ] **Step 3: Modify processEvents to filter staging paths**

In `processEvents`, replace the event handling block:

```go
// Only process write and create events for policy files
if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
	if isInStagingDir(event.Name, w.policyDir) {
		// Staging events: track by policy base name
		if isStagingRelevant(event.Name) {
			policyPath := stagingPolicyPath(event.Name)
			stagingPending[policyPath] = time.Now()
		}
	} else if isPolicyFile(event.Name) {
		pending[event.Name] = time.Now()
	}
}
```

Add a `stagingPending` map alongside `pending`:

```go
pending := make(map[string]time.Time)
stagingPending := make(map[string]time.Time)
```

Add staging debounce check in the ticker block:

```go
case <-ticker.C:
	now := time.Now()
	// Live reload debounce
	for path, lastChange := range pending {
		if now.Sub(lastChange) >= w.debounce {
			delete(pending, path)
			select {
			case w.reloadChan <- path:
			default:
			}
		}
	}
	// Staging debounce
	for path, lastChange := range stagingPending {
		if now.Sub(lastChange) >= w.stagingDebounce {
			delete(stagingPending, path)
			select {
			case w.stagingChan <- path:
			default:
			}
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/hotreload/ -run TestPolicyWatcher_StagingFileDoesNotTriggerLiveReload -v`
Expected: PASS

- [ ] **Step 5: Run all existing watcher tests to confirm no regression**

Run: `go test ./pkg/hotreload/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/hotreload/watcher.go pkg/hotreload/watcher_test.go
git commit -m "feat(hotreload): route staging events separately from live reloads"
```

---

### Task 3: Create .staging/ on Start, exclude from TriggerReload

**Files:**
- Modify: `pkg/hotreload/watcher.go`
- Test: `pkg/hotreload/watcher_test.go`

- [ ] **Step 1: Write failing test — .staging/ created on start**

```go
func TestPolicyWatcher_CreatesStagingDirOnStart(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	stagingDir := filepath.Join(dir, ".staging")
	info, err := os.Stat(stagingDir)
	if err != nil {
		t.Fatalf(".staging dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal(".staging is not a directory")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/hotreload/ -run TestPolicyWatcher_CreatesStagingDirOnStart -v`
Expected: FAIL — `.staging` not created

- [ ] **Step 3: Add .staging/ creation in Start() and exclude from TriggerReload**

In `Start()`, after creating the fsnotify watcher and before `addWatchRecursive`:

```go
// Ensure .staging directory exists for policy delivery
stagingDir := filepath.Join(w.policyDir, stagingDirName)
if err := os.MkdirAll(stagingDir, 0755); err != nil {
	watcher.Close()
	w.running.Store(false)
	return fmt.Errorf("creating staging directory: %w", err)
}
```

Start the staging goroutine alongside the existing ones:

```go
go w.processEvents(ctx)
go w.processReloads(ctx)
go w.processStagingReloads(ctx)
```

Add a stub for `processStagingReloads` (will be implemented in Task 4):

```go
func (w *PolicyWatcher) processStagingReloads(ctx context.Context) {
	for {
		select {
		case <-w.stagingChan:
			// TODO: implement in Task 4
		case <-ctx.Done():
			return
		}
	}
}
```

In `TriggerReload`, skip `.staging/`:

```go
func (w *PolicyWatcher) TriggerReload() error {
	if !w.running.Load() {
		return fmt.Errorf("watcher not running")
	}

	return filepath.Walk(w.policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip staging directory
		if info.IsDir() && info.Name() == stagingDirName {
			return filepath.SkipDir
		}
		if !info.IsDir() && isPolicyFile(path) {
			select {
			case w.reloadChan <- path:
			default:
				return fmt.Errorf("reload channel full")
			}
		}
		return nil
	})
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/hotreload/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/hotreload/watcher.go pkg/hotreload/watcher_test.go
git commit -m "feat(hotreload): create .staging/ on start, exclude from TriggerReload"
```

---

### Task 4: Implement staging validation, file promotion, and stats

**Files:**
- Modify: `pkg/hotreload/watcher.go`
- Test: `pkg/hotreload/watcher_test.go`

**Important:** This task adds staging stats fields (`StagingTotal`, `StagingSuccess`, `StagingFailed`) and a dedicated `recordStagingError` method upfront, so staging errors are never miscounted as reload errors.

- [ ] **Step 1: Add staging stats fields to WatcherStats**

Add to `WatcherStats` struct:

```go
StagingTotal   int64     `json:"staging_total"`
StagingSuccess int64     `json:"staging_success"`
StagingFailed  int64     `json:"staging_failed"`
```

Update `Stats()` to copy the new fields. Add `recordStagingError`:

```go
func (w *PolicyWatcher) recordStagingError(err string) {
	w.stats.mu.Lock()
	w.stats.StagingFailed++
	w.stats.LastError = err
	w.stats.LastErrorTime = time.Now()
	w.stats.mu.Unlock()
}
```

- [ ] **Step 2: Write failing test — valid staged policy moves to live dir**

```go
func TestPolicyWatcher_StagingPromotesValidPolicy(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}

	stagingDone := make(chan struct{}, 1)
	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write policy to staging
	os.WriteFile(filepath.Join(stagingDir, "test.yaml"), []byte("test: true"), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for staging processing")
	}

	// Policy should have been moved to live dir
	liveFile := filepath.Join(dir, "test.yaml")
	data, err := os.ReadFile(liveFile)
	if err != nil {
		t.Fatalf("policy not promoted to live dir: %v", err)
	}
	if string(data) != "test: true" {
		t.Fatalf("policy content mismatch: %q", data)
	}

	// Staging file should be gone
	if _, err := os.Stat(filepath.Join(stagingDir, "test.yaml")); !os.IsNotExist(err) {
		t.Fatal("staged policy should have been removed after promotion")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/hotreload/ -run TestPolicyWatcher_StagingPromotesValidPolicy -v`
Expected: FAIL — staging file not promoted

- [ ] **Step 3: Implement processStagingReloads and handleStagingFile**

Replace the `processStagingReloads` stub:

```go
func (w *PolicyWatcher) processStagingReloads(ctx context.Context) {
	for {
		select {
		case path := <-w.stagingChan:
			w.handleStagingFile(path)
		case <-ctx.Done():
			return
		}
	}
}

// handleStagingFile validates a staged policy and promotes it to the live directory.
func (w *PolicyWatcher) handleStagingFile(policyPath string) {
	// Ensure the policy file actually exists (might have been a .sig-only event)
	if _, err := os.Stat(policyPath); err != nil {
		return
	}

	w.stats.mu.Lock()
	w.stats.StagingTotal++
	w.stats.mu.Unlock()

	// Validate using the same loader as live reloads — this handles
	// signature verification based on the signing mode config.
	// Signing metadata logging (key_id, signer, signed_at) is the
	// responsibility of the Validate implementation, not the watcher.
	if err := w.loader.Validate(policyPath); err != nil {
		w.recordStagingError(fmt.Sprintf("staging validation failed %s: %v", filepath.Base(policyPath), err))
		if w.onStaging != nil {
			w.onStaging(policyPath, err)
		}
		return
	}

	// Promote to live directory: move .sig first (per design spec),
	// then .yaml. This ensures the live watcher always sees a .sig
	// if it sees the policy.
	baseName := filepath.Base(policyPath)
	sigName := baseName + ".sig"
	stagingDir := filepath.Dir(policyPath)

	stagingSig := filepath.Join(stagingDir, sigName)
	liveSig := filepath.Join(w.policyDir, sigName)
	livePolicy := filepath.Join(w.policyDir, baseName)

	// Move .sig first (may not exist in warn/off mode)
	if _, err := os.Stat(stagingSig); err == nil {
		if err := moveFile(stagingSig, liveSig); err != nil {
			w.recordStagingError(fmt.Sprintf("staging move sig %s: %v", sigName, err))
			if w.onStaging != nil {
				w.onStaging(policyPath, err)
			}
			return
		}
	}

	// Move policy file
	if err := moveFile(policyPath, livePolicy); err != nil {
		w.recordStagingError(fmt.Sprintf("staging move policy %s: %v", baseName, err))
		if w.onStaging != nil {
			w.onStaging(policyPath, err)
		}
		return
	}

	w.stats.mu.Lock()
	w.stats.StagingSuccess++
	w.stats.mu.Unlock()

	if w.onStaging != nil {
		w.onStaging(livePolicy, nil)
	}
}

// moveFile renames src to dst, replacing dst if it exists.
// Works cross-platform (Unix rename replaces atomically; Windows needs remove first).
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// Windows: Rename fails if dst exists. Remove and retry.
		os.Remove(dst)
		return os.Rename(src, dst)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/hotreload/ -run TestPolicyWatcher_StagingPromotesValidPolicy -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/hotreload/watcher.go pkg/hotreload/watcher_test.go
git commit -m "feat(hotreload): implement staging validation and file promotion"
```

---

### Task 5: Staging validation failure and .sig promotion tests

**Files:**
- Modify: `pkg/hotreload/watcher_test.go`

- [ ] **Step 1: Write test — validation failure leaves file in staging**

```go
func TestPolicyWatcher_StagingValidationFailureLeavesFile(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{
		validateFn: func(path string) error {
			return fmt.Errorf("missing_signature: no .sig file")
		},
	}

	stagingDone := make(chan error, 1)
	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			stagingDone <- err
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	stagedFile := filepath.Join(stagingDir, "bad.yaml")
	os.WriteFile(stagedFile, []byte("bad: true"), 0644)

	select {
	case err := <-stagingDone:
		if err == nil {
			t.Fatal("expected validation error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// File should remain in staging (not moved)
	if _, err := os.Stat(stagedFile); err != nil {
		t.Fatal("staged file should remain after validation failure")
	}

	// File should NOT appear in live dir
	if _, err := os.Stat(filepath.Join(dir, "bad.yaml")); !os.IsNotExist(err) {
		t.Fatal("failed policy should not appear in live dir")
	}
}
```

- [ ] **Step 2: Write test — .sig file is promoted alongside policy**

```go
func TestPolicyWatcher_StagingPromotesSigFile(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}
	stagingDone := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write .sig first, then .yaml (recommended order)
	os.WriteFile(filepath.Join(stagingDir, "signed.yaml.sig"), []byte(`{"version":1}`), 0644)
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(stagingDir, "signed.yaml"), []byte("signed: true"), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// Both files should be in live dir
	if _, err := os.Stat(filepath.Join(dir, "signed.yaml")); err != nil {
		t.Fatal("policy not promoted")
	}
	if _, err := os.Stat(filepath.Join(dir, "signed.yaml.sig")); err != nil {
		t.Fatal(".sig not promoted")
	}

	// Both should be gone from staging
	if _, err := os.Stat(filepath.Join(stagingDir, "signed.yaml")); !os.IsNotExist(err) {
		t.Fatal("staged policy should be removed")
	}
	if _, err := os.Stat(filepath.Join(stagingDir, "signed.yaml.sig")); !os.IsNotExist(err) {
		t.Fatal("staged .sig should be removed")
	}
}
```

- [ ] **Step 3: Write test — .yaml arrives first, .sig arrives within debounce window**

```go
func TestPolicyWatcher_StagingYamlFirstThenSig(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}
	stagingDone := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 500 * time.Millisecond, // Long enough for .sig to arrive
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write .yaml first
	os.WriteFile(filepath.Join(stagingDir, "delayed.yaml"), []byte("delayed: true"), 0644)
	// .sig arrives 100ms later (within 500ms staging debounce)
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(filepath.Join(stagingDir, "delayed.yaml.sig"), []byte(`{"version":1}`), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// Both files should be promoted
	if _, err := os.Stat(filepath.Join(dir, "delayed.yaml")); err != nil {
		t.Fatal("policy not promoted")
	}
	if _, err := os.Stat(filepath.Join(dir, "delayed.yaml.sig")); err != nil {
		t.Fatal(".sig not promoted")
	}
}
```

- [ ] **Step 4: Write test — staging policy overwrites existing live policy**

```go
func TestPolicyWatcher_StagingOverwritesExistingPolicy(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	// Pre-existing live policy
	os.WriteFile(filepath.Join(dir, "existing.yaml"), []byte("version: 1"), 0644)

	loader := &mockLoader{}
	stagingDone := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Stage updated version
	os.WriteFile(filepath.Join(stagingDir, "existing.yaml"), []byte("version: 2"), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	data, err := os.ReadFile(filepath.Join(dir, "existing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "version: 2" {
		t.Fatalf("expected overwritten content, got %q", data)
	}
}
```

**Note:** Add `"fmt"` to the test file imports for `fmt.Errorf` used in `TestPolicyWatcher_StagingValidationFailureLeavesFile`.

- [ ] **Step 5: Run all tests**

Run: `go test ./pkg/hotreload/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/hotreload/watcher_test.go
git commit -m "test(hotreload): add staging edge case tests"
```

---

### Task 6: Final build verification

- [ ] **Step 1: Run full build and cross-compile check**

```bash
go build ./...
GOOS=windows go build ./...
go test ./...
```

Expected: All pass, no compile errors on Windows.
