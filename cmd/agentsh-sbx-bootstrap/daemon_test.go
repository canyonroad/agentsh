package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSpawnDaemonAndWait_SocketAppears(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets only")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "agentsh.sock")

	// Fake "daemon": a shell script that writes the socket file after a small
	// delay. The bootstrap should observe it within the 2s window.
	fakeBin := filepath.Join(dir, "fake-agentsh")
	script := "#!/bin/sh\n(sleep 0.1; touch '" + sock + "') &\nexec sleep 5\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, "bootstrap.log")
	cmd, err := spawnDaemon(fakeBin, []string{"server"}, logPath)
	if err != nil {
		t.Fatalf("spawnDaemon: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	if err := waitForSocket(sock, 2*time.Second); err != nil {
		t.Fatalf("waitForSocket: %v", err)
	}
}

func TestWaitForSocket_TimesOut(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nope.sock")
	start := time.Now()
	err := waitForSocket(sock, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("waitForSocket overshot deadline: %v", elapsed)
	}
}

func TestWaitForSocket_NonExistError(t *testing.T) {
	// A path under a path component that is a regular file (not a directory)
	// makes os.Stat return ENOTDIR, not ENOENT — exercises the new
	// non-ErrNotExist branch.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(notADir, "agentsh.sock") // /tmp/.../file/agentsh.sock — ENOTDIR
	err := waitForSocket(sock, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected non-nil error for non-existent parent")
	}
	if !strings.Contains(err.Error(), "stat socket") {
		t.Errorf("expected wrapped stat error, got: %v", err)
	}
}
