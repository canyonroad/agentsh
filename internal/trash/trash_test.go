package trash

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDivertAndRestoreFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	entry, err := Divert(src, Config{TrashDir: filepath.Join(dir, ".trash"), Session: "s1", HashLimitBytes: 1 << 20})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("expected source removed, got err=%v", err)
	}
	if _, err := os.Stat(entry.TrashPath); err != nil {
		t.Fatalf("expected payload in trash: %v", err)
	}

	restored, err := Restore(filepath.Join(dir, ".trash"), entry.Token, "", false)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored != src {
		t.Fatalf("restore path mismatch: %s", restored)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(b) != "hello" {
		t.Fatalf("content mismatch: %q", string(b))
	}
	entries, err := List(filepath.Join(dir, ".trash"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected manifest cleaned up, got %d entries", len(entries))
	}
}

func TestDivertHashesSmallFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "tiny.txt")
	if err := os.WriteFile(src, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry, err := Divert(src, Config{TrashDir: filepath.Join(dir, ".trash"), Session: "s1", HashLimitBytes: 10})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}
	if entry.Hash == "" || entry.HashAlgo != "sha256" {
		t.Fatalf("expected hash recorded, got hash=%q algo=%q", entry.Hash, entry.HashAlgo)
	}
	entries, err := List(filepath.Join(dir, ".trash"))
	if err != nil || len(entries) != 1 || entries[0].Hash != entry.Hash {
		t.Fatalf("manifest missing hash: %+v", entries)
	}
}

func TestPurgeByQuota(t *testing.T) {
	dir := t.TempDir()
	trashDir := filepath.Join(dir, ".trash")

	makeFile := func(name string, size int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	f1 := makeFile("a.txt", 1024)
	_, _ = Divert(f1, Config{TrashDir: trashDir, Session: "s1"})
	time.Sleep(5 * time.Millisecond) // ensure ordering
	f2 := makeFile("b.txt", 1024)
	e2, _ := Divert(f2, Config{TrashDir: trashDir, Session: "s1"})

	removed, err := Purge(trashDir, PurgeOptions{QuotaBytes: 1500, Now: time.Now()})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected to remove 1 entry, got %d", removed)
	}
	entries, _ := List(trashDir)
	if len(entries) != 1 || entries[0].Token != e2.Token {
		t.Fatalf("expected newer entry to remain, got %+v", entries)
	}
}

func TestPurgeByTTL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mtime handling flaky on windows")
	}
	dir := t.TempDir()
	trashDir := filepath.Join(dir, ".trash")
	src := filepath.Join(dir, "old.txt")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Divert(src, Config{TrashDir: trashDir, Session: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(48 * time.Hour)
	removed, err := Purge(trashDir, PurgeOptions{TTL: 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	entries, _ := List(trashDir)
	if len(entries) != 0 {
		t.Fatalf("expected empty trash after purge, got %d", len(entries))
	}
}

func TestPurgeWithResultDryRun(t *testing.T) {
	dir := t.TempDir()
	trashDir := filepath.Join(dir, ".trash")
	src := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(src, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	entry, err := Divert(src, Config{TrashDir: trashDir, Session: "s1"})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}

	// DryRun should report but not remove
	now := time.Now().Add(48 * time.Hour)
	result, err := PurgeWithResult(trashDir, PurgeOptions{
		TTL:    24 * time.Hour,
		Now:    now,
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if result.EntriesRemoved != 1 {
		t.Fatalf("expected 1 entry in result, got %d", result.EntriesRemoved)
	}
	if result.BytesReclaimed != entry.Size {
		t.Fatalf("expected %d bytes reclaimed, got %d", entry.Size, result.BytesReclaimed)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry in Entries list, got %d", len(result.Entries))
	}

	// Entry should still exist after DryRun
	entries, _ := List(trashDir)
	if len(entries) != 1 {
		t.Fatalf("expected entry to still exist after DryRun, got %d", len(entries))
	}
}

func TestPurgeByQuotaCount(t *testing.T) {
	dir := t.TempDir()
	trashDir := filepath.Join(dir, ".trash")

	makeFile := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Create 3 files
	f1 := makeFile("a.txt")
	_, _ = Divert(f1, Config{TrashDir: trashDir, Session: "s1"})
	time.Sleep(5 * time.Millisecond)
	f2 := makeFile("b.txt")
	_, _ = Divert(f2, Config{TrashDir: trashDir, Session: "s1"})
	time.Sleep(5 * time.Millisecond)
	f3 := makeFile("c.txt")
	e3, _ := Divert(f3, Config{TrashDir: trashDir, Session: "s1"})

	// Keep only 1 entry
	result, err := PurgeWithResult(trashDir, PurgeOptions{QuotaCount: 1})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if result.EntriesRemoved != 2 {
		t.Fatalf("expected 2 removed, got %d", result.EntriesRemoved)
	}

	entries, _ := List(trashDir)
	if len(entries) != 1 || entries[0].Token != e3.Token {
		t.Fatalf("expected newest entry to remain, got %+v", entries)
	}
}

func TestEntryHasPlatform(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	entry, err := Divert(src, Config{TrashDir: filepath.Join(dir, ".trash"), Session: "s1"})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}

	if entry.Platform == "" {
		t.Error("expected Platform to be set")
	}
	if entry.Platform != runtime.GOOS {
		t.Errorf("expected Platform=%s, got %s", runtime.GOOS, entry.Platform)
	}
}

func TestDivertWithXattrs(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("xattr test only runs on Linux and macOS")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Set an xattr (this may fail if xattrs not supported)
	// We use user. prefix on Linux
	xattrName := "user.testattr"
	if runtime.GOOS == "darwin" {
		xattrName = "com.test.attr"
	}
	if err := setXattr(src, xattrName, []byte("testvalue")); err != nil {
		t.Skipf("xattrs not supported: %v", err)
	}

	entry, err := Divert(src, Config{
		TrashDir:       filepath.Join(dir, ".trash"),
		Session:        "s1",
		PreserveXattrs: true,
	})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}

	if len(entry.Xattrs) == 0 {
		t.Error("expected xattrs to be captured")
	}

	found := false
	for _, x := range entry.Xattrs {
		if x.Name == xattrName {
			found = true
			if string(x.Value) != "testvalue" {
				t.Errorf("xattr value mismatch: got %q", string(x.Value))
			}
		}
	}
	if !found {
		t.Errorf("expected xattr %s to be captured, got %v", xattrName, entry.Xattrs)
	}
}
