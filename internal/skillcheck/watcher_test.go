package skillcheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcher_DetectsNewSkill(t *testing.T) {
	root := t.TempDir()
	events := make(chan string, 4)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{root},
		Debounce: 50 * time.Millisecond,
		OnSkill: func(skillDir string) {
			events <- skillDir
		},
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()

	// Allow watcher to register root watch.
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "test-skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: test\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-events:
		if got != skillDir {
			t.Errorf("got=%s want=%s", got, skillDir)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect new skill within 2s")
	}
}

func TestWatcher_DebounceCoalesces(t *testing.T) {
	root := t.TempDir()
	events := make(chan string, 16)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{root},
		Debounce: 200 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "skill-a")
	os.MkdirAll(skillDir, 0o755)
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("v"), 0o644)
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)
	got := drain(events)
	if got != 1 {
		t.Errorf("expected 1 debounced event, got %d", got)
	}
}

func drain(ch chan string) int {
	n := 0
	for {
		select {
		case <-ch:
			n++
		default:
			return n
		}
	}
}

func TestWatcher_DetectsNestedSkillInAtomicTree(t *testing.T) {
	root := t.TempDir()
	events := make(chan string, 8)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{root},
		Debounce: 50 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	// Atomic-ish creation: rename a fully populated tree into the watched root.
	staging := t.TempDir()
	nestedSkill := filepath.Join(staging, "outer", "inner-skill")
	if err := os.MkdirAll(nestedSkill, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nestedSkill, "SKILL.md"), []byte("---\nname: nested\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	moved := filepath.Join(root, "outer")
	if err := os.Rename(filepath.Join(staging, "outer"), moved); err != nil {
		t.Fatalf("rename: %v", err)
	}

	expected := filepath.Join(moved, "inner-skill")
	select {
	case got := <-events:
		if got != expected {
			t.Errorf("got %s want %s", got, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect nested SKILL.md within 2s")
	}
}

func TestWatcher_DetectsRootCreatedAfterStart(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "skills") // doesn't exist yet
	events := make(chan string, 4)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{rootPath},
		Debounce: 50 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	// Now create the root and a skill inside it.
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	skillDir := filepath.Join(rootPath, "first")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: first\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-events:
		if got != skillDir {
			t.Errorf("got %s want %s", got, skillDir)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect skill in root that appeared after start")
	}
}

func TestWatcher_DeepNestedRootMissing(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "level1", "level2", "skills") // grandgrand-parent only

	events := make(chan string, 8)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{rootPath},
		Debounce: 50 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	// Create the chain incrementally.
	for _, sub := range []string{"level1", "level1/level2", "level1/level2/skills"} {
		if err := os.MkdirAll(filepath.Join(parent, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
		time.Sleep(150 * time.Millisecond) // let watcher cascade
	}

	skillDir := filepath.Join(rootPath, "first")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: first\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-events:
		if got != skillDir {
			t.Errorf("got %s want %s", got, skillDir)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect skill in deeply-nested root that appeared after start")
	}
}

func TestWatcher_GlobMatchesMultiplePluginsOverTime(t *testing.T) {
	parent := t.TempDir()
	pluginsDir := filepath.Join(parent, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}
	rootGlob := filepath.Join(pluginsDir, "*", "skills")

	events := make(chan string, 16)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{rootGlob},
		Debounce: 50 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	// First plugin lands.
	plugA := filepath.Join(pluginsDir, "plug-a", "skills")
	skillA := filepath.Join(plugA, "skill-a")
	if err := os.MkdirAll(skillA, 0o755); err != nil {
		t.Fatalf("mkdir A: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillA, "SKILL.md"), []byte("---\nname: a\n---\n"), 0o644); err != nil {
		t.Fatalf("write A: %v", err)
	}

	// Second plugin lands LATER.
	time.Sleep(300 * time.Millisecond)
	plugB := filepath.Join(pluginsDir, "plug-b", "skills")
	skillB := filepath.Join(plugB, "skill-b")
	if err := os.MkdirAll(skillB, 0o755); err != nil {
		t.Fatalf("mkdir B: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillB, "SKILL.md"), []byte("---\nname: b\n---\n"), 0o644); err != nil {
		t.Fatalf("write B: %v", err)
	}

	seen := map[string]bool{}
	deadline := time.After(3 * time.Second)
	for len(seen) < 2 {
		select {
		case got := <-events:
			seen[got] = true
		case <-deadline:
			t.Fatalf("only saw %d events for two distinct plugins; events: %v", len(seen), seen)
		}
	}
	if !seen[skillA] || !seen[skillB] {
		t.Errorf("missing detection: A=%v B=%v", seen[skillA], seen[skillB])
	}
}

func TestWatcher_GlobStaticAncestorAppearsAfterStart(t *testing.T) {
	parent := t.TempDir()
	pluginsDir := filepath.Join(parent, "plugins") // doesn't exist yet
	rootGlob := filepath.Join(pluginsDir, "*", "skills")

	events := make(chan string, 8)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{rootGlob},
		Debounce: 50 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	// Now create the static ancestor of the glob.
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// Then a plugin appears.
	plug := filepath.Join(pluginsDir, "plug-a", "skills")
	skill := filepath.Join(plug, "first")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatalf("mkdir plug: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: first\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-events:
		if got != skill {
			t.Errorf("got %s want %s", got, skill)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect skill after glob ancestor appeared post-start")
	}
}

func TestWatcher_AtomicLiteralRootCreation(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "deeply", "nested", "skills")

	events := make(chan string, 8)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{rootPath},
		Debounce: 50 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	// Atomic-ish: MkdirAll creates the entire chain plus a skill in one go.
	skill := filepath.Join(rootPath, "first")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: first\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-events:
		if got != skill {
			t.Errorf("got %s want %s", got, skill)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect skill in atomically-created chain")
	}
}

func TestWatcher_DoesNotFireOnSiblingsOfMissingRoot(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "skills") // doesn't exist yet
	siblingPath := filepath.Join(parent, "unrelated")

	events := make(chan string, 8)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{rootPath},
		Debounce: 50 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	// Create a sibling skill that should NOT fire OnSkill (it's outside the
	// configured root, but under the watched ancestor).
	siblingSkill := filepath.Join(siblingPath, "noisy")
	if err := os.MkdirAll(siblingSkill, 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	if err := os.WriteFile(filepath.Join(siblingSkill, "SKILL.md"), []byte("---\nname: noisy\n---\n"), 0o644); err != nil {
		t.Fatalf("write sibling: %v", err)
	}

	// Wait long enough that any spurious debounce would have fired.
	time.Sleep(300 * time.Millisecond)
	select {
	case got := <-events:
		t.Errorf("OnSkill fired for sibling outside watch root: %s", got)
	default:
		// good
	}

	// Now legitimately create the configured root and a skill inside it.
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	realSkill := filepath.Join(rootPath, "ok")
	if err := os.MkdirAll(realSkill, 0o755); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realSkill, "SKILL.md"), []byte("---\nname: ok\n---\n"), 0o644); err != nil {
		t.Fatalf("write real: %v", err)
	}

	select {
	case got := <-events:
		if got != realSkill {
			t.Errorf("got %s want %s", got, realSkill)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect skill in legitimately-created root")
	}
}
