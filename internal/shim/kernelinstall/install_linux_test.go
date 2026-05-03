//go:build linux

package kernelinstall

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// makeWrapInitHandler returns an http.HandlerFunc that serves the given
// response body and status code on POST /api/v1/sessions/.../wrap-init.
func makeWrapInitHandler(status int, resp any) (http.HandlerFunc, *int) {
	calls := new(int)
	return func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if !strings.Contains(r.URL.Path, "/wrap-init") {
			http.NotFound(w, r)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "server error", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}, calls
}

func baseParams(srv *httptest.Server) InstallParams {
	return InstallParams{
		ServerBaseURL: srv.URL,
		SessionID:     "test-session",
		APIKey:        "test-key",
		RealShell:     "/bin/sh",
		ShellArgs:     []string{"-c", "echo hello"},
		Env:           []string{"HOME=/tmp"},
	}
}

// ─── Test 1: ModeOff returns ResultSkip without any HTTP call ───────────────

func TestInstall_ModeOff_ReturnsSkip(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: "/usr/bin/agentsh-unixwrap",
		NotifySocket:  "/tmp/notify.sock",
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOff

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v", res.Action)
	}
	if *calls != 0 {
		t.Errorf("expected 0 HTTP calls, got %d", *calls)
	}
}

// ─── Test 2: ModeAuto + server 500 → ResultSkip ─────────────────────────────

func TestInstall_ModeAuto_WrapInitError_Skips(t *testing.T) {
	handler, _ := makeWrapInitHandler(500, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v", res.Action)
	}
}

// ─── Test 3: ModeOn + server 500 → ResultFailClosed ─────────────────────────

func TestInstall_ModeOn_WrapInitError_FailsClosed(t *testing.T) {
	handler, _ := makeWrapInitHandler(500, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultFailClosed {
		t.Errorf("expected ResultFailClosed, got %v", res.Action)
	}
	if res.Reason == "" {
		t.Error("expected non-empty Reason")
	}
}

// ─── Test 4: ModeAuto + empty WrapInitResponse → ResultSkip ─────────────────

func TestInstall_ModeAuto_EmptyResponse_Skips(t *testing.T) {
	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v", res.Action)
	}
}

// ─── Test 5: ModeOn + empty WrapInitResponse → ResultFailClosed ─────────────

func TestInstall_ModeOn_EmptyResponse_FailsClosed(t *testing.T) {
	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultFailClosed {
		t.Errorf("expected ResultFailClosed, got %v", res.Action)
	}
}

// ─── Test 6: AGENTSH_SIGNAL_SOCK_FD is stripped from WrapperEnv ─────────────

func TestInstall_StripsSignalSockFd(t *testing.T) {
	// Build env with signal sock fd and another var.
	env := []string{
		"AGENTSH_SIGNAL_SOCK_FD=4",
		"OTHER=x",
		"HOME=/tmp",
	}

	filtered := filterSignalSockFD(env)

	for _, e := range filtered {
		if strings.HasPrefix(e, "AGENTSH_SIGNAL_SOCK_FD=") {
			t.Errorf("AGENTSH_SIGNAL_SOCK_FD was not stripped: %q", e)
		}
	}
	found := false
	for _, e := range filtered {
		if e == "OTHER=x" {
			found = true
		}
	}
	if !found {
		t.Error("OTHER=x was unexpectedly removed")
	}
}

// ─── Test 7: full relay happy-path ───────────────────────────────────────────
//
// This test builds a tiny fake-wrapper binary (Go) that implements the wrapper
// side of the socketpair protocol:
//   1. Reads fd 3 (child end of the socketpair).
//   2. Dups fd 3 and sends the dup back via SCM_RIGHTS (as stand-in notify fd).
//   3. Reads the ACK byte.
//   4. Exits with code 42.
//
// The fake server listener accepts the forwarded fd and closes immediately.
// If the Go toolchain is unavailable the test is skipped.

func TestInstall_RelayHappyPath(t *testing.T) {
	// Build the fake wrapper binary.
	wrapperBin := buildFakeWrapper(t)

	// Start a fake notify-socket listener.
	sockDir := t.TempDir()
	notifySockPath := sockDir + "/notify.sock"
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept and close in background (emulates server receiving the notify fd).
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			// Drain SCM_RIGHTS payload so the sender doesn't block.
			buf := make([]byte, 1)
			oob := make([]byte, 64)
			conn.(*net.UnixConn).ReadMsgUnix(buf, oob) //nolint:errcheck
			conn.Close()
		}
	}()

	// httptest server that returns a populated WrapInitResponse.
	wrapResp := types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySockPath,
		WrapperEnv:    map[string]string{"FAKE_WRAPPER": "1"},
	}
	handler, _ := makeWrapInitHandler(200, wrapResp)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("expected ResultExec, got %v (reason: %s)", res.Action, res.Reason)
	}
	if res.WrapperExitCode != 42 {
		t.Errorf("expected wrapper exit code 42, got %d", res.WrapperExitCode)
	}
}

// ─── fake wrapper builder ────────────────────────────────────────────────────

const fakeWrapperSrc = `package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	sock := 3

	notifyFD, err := unix.Dup(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake-wrapper: dup: %v\n", err)
		os.Exit(1)
	}

	rights := unix.UnixRights(notifyFD)
	if err := unix.Sendmsg(sock, []byte{0}, rights, nil, 0); err != nil {
		fmt.Fprintf(os.Stderr, "fake-wrapper: sendmsg: %v\n", err)
		os.Exit(1)
	}
	unix.Close(notifyFD)

	ack := make([]byte, 1)
	if _, err := unix.Read(sock, ack); err != nil {
		fmt.Fprintf(os.Stderr, "fake-wrapper: read ack: %v\n", err)
		os.Exit(1)
	}

	os.Exit(42)
}
`

// buildFakeWrapper compiles a tiny Go program into a temp dir by building it
// within the parent module so the replace directive is already in place.
// It copies main.go into a subdirectory of the parent module tree and uses
// a build tag to isolate it from the normal build.  If compilation fails the
// test is skipped.
func buildFakeWrapper(t *testing.T) string {
	t.Helper()

	goExe, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not found in PATH; skipping relay happy-path test")
	}

	// Write the fake wrapper source inside the parent module (a temp subdir)
	// so it can use the module's existing go.mod / go.sum and dependencies.
	modRoot := findModuleRoot(t)
	srcDir, err := os.MkdirTemp(modRoot, "fakewrapper_src_*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(srcDir) })

	if err := os.WriteFile(srcDir+"/main.go", []byte(fakeWrapperSrc), 0644); err != nil {
		t.Fatalf("write fake wrapper source: %v", err)
	}

	binDir := t.TempDir()
	binPath := binDir + "/fakewrap"

	buildCmd := exec.Command(goExe, "build", "-o", binPath, srcDir)
	buildCmd.Dir = modRoot
	out, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Skipf("compile fake wrapper: %v\n%s", err, out)
	}
	return binPath
}

// findModuleRoot walks up from the current working directory to find go.mod.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		idx := strings.LastIndex(dir, "/")
		if idx <= 0 {
			t.Fatal("could not find go.mod")
		}
		dir = dir[:idx]
	}
}
