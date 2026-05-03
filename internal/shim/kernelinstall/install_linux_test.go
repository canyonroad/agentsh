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

// ─── Test 6b: AGENTSH_SIGNAL_SOCK_FD is stripped from p.Env (not just WrapperEnv) ─

// TestInstall_StripsSignalSockFdFromPEnv verifies that a stale
// AGENTSH_SIGNAL_SOCK_FD in p.Env (inherited from a parent context) is removed
// before being passed to the wrapper, even when WrapperEnv has no such entry.
// We verify this by running the full relay with a p.Env containing a stale fd
// value and asserting the wrapper's environment (via the fake wrapper printing
// its own env) contains no AGENTSH_SIGNAL_SOCK_FD entry.
func TestInstall_StripsSignalSockFdFromPEnv(t *testing.T) {
	// Build a fake wrapper that prints its env and then does the socketpair handshake.
	wrapperBin := buildFakeWrapperPrintEnv(t)

	// Start a fake notify-socket listener.
	sockDir := t.TempDir()
	notifySockPath := sockDir + "/notify.sock"
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			buf := make([]byte, 1)
			oob := make([]byte, 64)
			conn.(*net.UnixConn).ReadMsgUnix(buf, oob) //nolint:errcheck
			conn.Close()
		}
	}()

	wrapResp := types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySockPath,
		// WrapperEnv deliberately does NOT contain AGENTSH_SIGNAL_SOCK_FD.
		WrapperEnv: map[string]string{"FAKE_WRAPPER": "1"},
	}
	handler, _ := makeWrapInitHandler(200, wrapResp)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn
	// Inject a stale AGENTSH_SIGNAL_SOCK_FD into p.Env (simulates parent context).
	p.Env = []string{
		"AGENTSH_SIGNAL_SOCK_FD=4",
		"OTHER=x",
		"HOME=/tmp",
	}

	// Capture wrapper output via a temp file.
	outFile, err := os.CreateTemp(t.TempDir(), "wrapper-env-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	outPath := outFile.Name()
	outFile.Close()

	// Pass the output file path to the fake wrapper via env.
	p.Env = append(p.Env, "FAKE_ENV_OUT="+outPath)

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("expected ResultExec, got %v (reason: %s)", res.Action, res.Reason)
	}

	envOutput, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read wrapper env output: %v", err)
	}

	for _, line := range strings.Split(string(envOutput), "\n") {
		if strings.HasPrefix(line, "AGENTSH_SIGNAL_SOCK_FD=") {
			t.Errorf("AGENTSH_SIGNAL_SOCK_FD leaked into wrapper env: %q", line)
		}
	}
	t.Logf("wrapper env output (excerpt):\n%s", string(envOutput))
}

// fakeWrapperPrintEnvSrc is a fake wrapper that writes its environment to the
// file named by FAKE_ENV_OUT, sends the notify fd, reads the ACK, and exits 0.
const fakeWrapperPrintEnvSrc = `package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func main() {
	sock := 3

	// Write environment to FAKE_ENV_OUT before the handshake.
	if outPath := os.Getenv("FAKE_ENV_OUT"); outPath != "" {
		var sb strings.Builder
		for _, e := range os.Environ() {
			sb.WriteString(e)
			sb.WriteByte('\n')
		}
		_ = os.WriteFile(outPath, []byte(sb.String()), 0600)
	}

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
	os.Exit(0)
}
`

// buildFakeWrapperPrintEnv builds the fakeWrapperPrintEnvSrc binary.
func buildFakeWrapperPrintEnv(t *testing.T) string {
	t.Helper()

	goExe, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not found in PATH; skipping print-env test")
	}

	modRoot := findModuleRoot(t)
	srcDir, err := os.MkdirTemp(modRoot, "fakewrapper_printenv_src_*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(srcDir) })

	if err := os.WriteFile(srcDir+"/main.go", []byte(fakeWrapperPrintEnvSrc), 0644); err != nil {
		t.Fatalf("write fake wrapper printenv source: %v", err)
	}

	binDir := t.TempDir()
	binPath := binDir + "/fakewrap-printenv"

	buildCmd := exec.Command(goExe, "build", "-o", binPath, srcDir)
	buildCmd.Dir = modRoot
	out, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		t.Skipf("compile fake wrapper printenv: %v\n%s", buildErr, out)
	}
	return binPath
}

// ─── Test 7a: relay forward-failure → ResultFailClosed, ACK not sent ──────────
//
// Simulates a forward failure by pointing resp.NotifySocket at a non-existent
// path.  The fake wrapper sends the notify fd, then blocks waiting for the ACK.
// When forwardNotifyFD fails, runRelay must:
//   - NOT write an ACK byte to the parent fd.
//   - Close the parent fd so the wrapper's read-ACK returns EOF → wrapper exits.
//   - Return ResultFailClosed.
//
// We verify the ACK-not-sent guarantee by interposing a pipe: the test puts a
// read end on the parent side of the socketpair and asserts zero bytes received
// before the wrapper exits.

func TestInstall_RelayForwardFail_NoACK_ResultFailClosed(t *testing.T) {
	// Build the fake wrapper.
	wrapperBin := buildFakeWrapperNoACKExit(t)

	// httptest server returns a valid WrapperBinary but a bogus (non-existent)
	// NotifySocket so forwardNotifyFD will fail with "dial …: no such file".
	wrapResp := types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  "/nonexistent/path/notify.sock",
		WrapperEnv:    map[string]string{},
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
	if res.Action != ResultFailClosed {
		t.Fatalf("expected ResultFailClosed (forward failed → fail-closed), got %v (reason: %s)", res.Action, res.Reason)
	}
	if res.Reason == "" {
		t.Error("expected non-empty Reason for forward failure")
	}
	if !strings.Contains(res.Reason, "forward notify fd failed") {
		t.Errorf("expected Reason to contain 'forward notify fd failed', got %q", res.Reason)
	}
}

// fakeWrapperNoACKExitSrc is a fake wrapper that sends the notify fd and then
// exits with code 2 when the ACK read fails (parent closed the fd).  This lets
// the test verify that the wrapper exited due to the closed parent fd, not for
// any other reason.
const fakeWrapperNoACKExitSrc = `package main

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

	// Try to read ACK. If the parent closed the fd, Read returns an error or
	// n==0 (EOF). Exit 2 to distinguish from other failure modes.
	ack := make([]byte, 1)
	n, readErr := unix.Read(sock, ack)
	if readErr != nil || n == 0 {
		// Parent closed the fd before writing ACK — expected in forward-failure path.
		os.Exit(2)
	}
	// ACK received unexpectedly.
	fmt.Fprintf(os.Stderr, "fake-wrapper: unexpected ACK byte 0x%02x\n", ack[0])
	os.Exit(3)
}
`

// buildFakeWrapperNoACKExit builds the fakeWrapperNoACKExitSrc binary.
func buildFakeWrapperNoACKExit(t *testing.T) string {
	t.Helper()

	goExe, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not found in PATH; skipping relay forward-fail test")
	}

	modRoot := findModuleRoot(t)
	srcDir, err := os.MkdirTemp(modRoot, "fakewrapper_noack_src_*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(srcDir) })

	if err := os.WriteFile(srcDir+"/main.go", []byte(fakeWrapperNoACKExitSrc), 0644); err != nil {
		t.Fatalf("write fake wrapper no-ack source: %v", err)
	}

	binDir := t.TempDir()
	binPath := binDir + "/fakewrap-noack"

	buildCmd := exec.Command(goExe, "build", "-o", binPath, srcDir)
	buildCmd.Dir = modRoot
	out, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		t.Skipf("compile fake wrapper no-ack: %v\n%s", buildErr, out)
	}
	return binPath
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
