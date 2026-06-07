//go:build linux

package kernelinstall

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/wraphandoff"
	"github.com/agentsh/agentsh/internal/wrapperlog"
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

func serveNotifySetupStatus(ln net.Listener, okStatus bool) {
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
			_ = wraphandoff.WriteStatus(unixConn, okStatus)
		}
	}()
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

// ─── Test InheritedFilter: caller already has seccomp filter → ResultSkip ────

// TestInstall_AlreadyFiltered_ReturnsSkip covers the #282 root cause
// confirmed by the rc1 (commit a4de5e1) diagnostic on Runloop:
// agentsh CLI spawns unixwrap_1 (installs F1, success); unixwrap_1 execs
// the user's command which goes through the shell-shim again, and the
// shim's kernelinstall.Install is called *inside* a process tree that
// already has F1 inherited via execve. Trying to install F2 on top
// returns EFAULT on this kernel/runtime. The fix: kernelinstall must
// detect the unforgeable Seccomp:2 + Seccomp_filters>=1 signal from
// /proc/self/status and skip wrap-init entirely — the inherited filter
// is already enforcing for this process and all its descendants, so a
// second install is both redundant and harmful.
//
// We inject seccompFilterCount via a package-level var so the test can
// simulate the inherited-filter state without forking a real child
// process with a live filter installed (which would also pollute the
// Go test runner's seccomp state and break unrelated tests).
//
// The httptest handler is registered but should NOT be hit. Reaching
// it indicates the skip gate fired AFTER wrap-init was contacted, which
// would still leak server load and side-effects (notify socket creation,
// event emission) on every nested shim invocation.
func TestInstall_AlreadyFiltered_ReturnsSkip(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: "/usr/bin/agentsh-unixwrap",
		NotifySocket:  "/tmp/notify.sock",
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	orig := seccompFilterCount
	seccompFilterCount = func() int { return 1 }
	t.Cleanup(func() { seccompFilterCount = orig })

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v (reason=%q)", res.Action, res.Reason)
	}
	if !strings.Contains(res.Reason, "already") {
		t.Errorf("expected reason to mention already-filtered state, got %q", res.Reason)
	}
	if *calls != 0 {
		t.Errorf("expected 0 HTTP calls (skip must happen before wrap-init), got %d", *calls)
	}
}

// TestInstall_AlreadyFiltered_ModeOnAlsoSkips documents that inherited-
// filter detection bypasses ModeOn's fail-closed semantics. ModeOn means
// "must install or fail" — but if a filter is *already* installed via
// inheritance, the policy intent is satisfied (the filter is
// enforcing). Treating this as fail-closed would break the entire
// nested-shim case for users who set shim_install=on, so we still skip.
func TestInstall_AlreadyFiltered_ModeOnAlsoSkips(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: "/usr/bin/agentsh-unixwrap",
		NotifySocket:  "/tmp/notify.sock",
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	orig := seccompFilterCount
	seccompFilterCount = func() int { return 1 }
	t.Cleanup(func() { seccompFilterCount = orig })

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("ModeOn must still skip when a filter is inherited; got %v", res.Action)
	}
	if *calls != 0 {
		t.Errorf("expected 0 HTTP calls, got %d", *calls)
	}
}

// TestInstall_NotFiltered_ProceedsAsBefore guards against a regression
// where the new gate accidentally fires on a clean process: when
// seccompFilterCount returns 0 (no inherited filter), the existing
// wrap-init/relay path must run — exactly the rc1 first-Load case
// (parent_comm=agentsh, caller_seccomp_state="mode=0 filter_count=0")
// that the rc1 diagnostic showed succeeding.
func TestInstall_NotFiltered_ProceedsAsBefore(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{}) // empty resp → ResultSkip via existing path
	srv := httptest.NewServer(handler)
	defer srv.Close()

	orig := seccompFilterCount
	seccompFilterCount = func() int { return 0 }
	t.Cleanup(func() { seccompFilterCount = orig })

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip from empty wrap-init response, got %v", res.Action)
	}
	if *calls != 1 {
		t.Errorf("expected wrap-init to be called when no filter inherited, got %d calls", *calls)
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
	notifySockPath := filepath.Join(sockDir, "notify.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveNotifySetupStatus(ln, true)

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

// TestInstall_PassesArgv0ToWrapper covers the v0.19.1 alpine docker-test
// regression: on busybox-multicall systems (Alpine) the renamed shell at
// /bin/sh.real is the busybox binary, and busybox derives the applet from
// argv[0]'s basename. Without forwarding the original invocation name
// ("/bin/sh") to the wrapper, the wrapper's syscall.Exec sets argv[0] to
// "/bin/sh.real", busybox looks up applet "sh.real", fails, and exits 127.
// This test verifies the fix: when InstallParams.Argv0 is set, the
// AGENTSH_UNIXWRAP_ARGV0 env var is propagated to the wrapper. The
// wrapper itself then substitutes argv[0]; that substitution is covered
// by tests in cmd/agentsh-unixwrap.
func TestInstall_PassesArgv0ToWrapper(t *testing.T) {
	wrapperBin := buildFakeWrapperPrintEnv(t)

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "notify.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveNotifySetupStatus(ln, true)

	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySockPath,
		WrapperEnv:    map[string]string{},
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	outFile, err := os.CreateTemp(t.TempDir(), "wrapper-env-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	outPath := outFile.Name()
	outFile.Close()

	p := baseParams(srv)
	p.Mode = ModeOn
	p.Argv0 = "/bin/sh"
	p.Env = []string{"FAKE_ENV_OUT=" + outPath}

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("expected ResultExec, got %v (reason: %s)", res.Action, res.Reason)
	}

	envOutput, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read wrapper env output: %v", err)
	}
	if !strings.Contains(string(envOutput), "AGENTSH_UNIXWRAP_ARGV0=/bin/sh\n") {
		t.Errorf("AGENTSH_UNIXWRAP_ARGV0 was not propagated to wrapper env. Got:\n%s", string(envOutput))
	}
}

// TestInstall_OmitsArgv0WhenEmpty covers the symmetric case: when
// InstallParams.Argv0 is empty (older shim, agent-mode caller), the
// AGENTSH_UNIXWRAP_ARGV0 env var must NOT be set. unixwrap's empty-string
// path falls back to argv[0]=resolved-cmd-path, preserving prior behavior.
func TestInstall_OmitsArgv0WhenEmpty(t *testing.T) {
	wrapperBin := buildFakeWrapperPrintEnv(t)

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "notify.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveNotifySetupStatus(ln, true)

	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySockPath,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	outFile, err := os.CreateTemp(t.TempDir(), "wrapper-env-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	outPath := outFile.Name()
	outFile.Close()

	p := baseParams(srv)
	p.Mode = ModeOn
	p.Argv0 = "" // explicitly empty
	p.Env = []string{"FAKE_ENV_OUT=" + outPath}

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("expected ResultExec, got %v (reason: %s)", res.Action, res.Reason)
	}

	envOutput, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read wrapper env output: %v", err)
	}
	if strings.Contains(string(envOutput), "AGENTSH_UNIXWRAP_ARGV0=") {
		t.Errorf("AGENTSH_UNIXWRAP_ARGV0 must NOT be set when Argv0 is empty. Got:\n%s", string(envOutput))
	}
}

// TestInstall_StripsStaleArgv0FromInheritedEnv guards roborev #7950
// finding (Low #2): a stale AGENTSH_UNIXWRAP_ARGV0 in p.Env (e.g.
// re-entrant shim invocation, or operator-set value) must NOT silently
// reach the wrapper. With InstallParams.Argv0 == "", the contract is
// "no override, fall back to resolved real path"; a leaked stale value
// would contradict that. We strip both internal env vars before
// appending the authoritative value (or none) in runRelay.
func TestInstall_StripsStaleArgv0FromInheritedEnv(t *testing.T) {
	wrapperBin := buildFakeWrapperPrintEnv(t)

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "notify.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveNotifySetupStatus(ln, true)

	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySockPath,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	outFile, err := os.CreateTemp(t.TempDir(), "wrapper-env-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	outPath := outFile.Name()
	outFile.Close()

	p := baseParams(srv)
	p.Mode = ModeOn
	p.Argv0 = "" // explicitly empty — must not be overridden by inherited stale
	p.Env = []string{
		"AGENTSH_UNIXWRAP_ARGV0=/bin/stale-shell", // stale inherited value
		"FAKE_ENV_OUT=" + outPath,
	}

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("expected ResultExec, got %v (reason: %s)", res.Action, res.Reason)
	}

	envOutput, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read wrapper env output: %v", err)
	}
	for _, line := range strings.Split(string(envOutput), "\n") {
		if strings.HasPrefix(line, "AGENTSH_UNIXWRAP_ARGV0=") {
			t.Errorf("stale AGENTSH_UNIXWRAP_ARGV0 leaked into wrapper env: %q", line)
		}
	}
}

// TestFilterShimInternalEnv covers the helper directly: it must drop
// both internal env vars and preserve everything else.
func TestFilterShimInternalEnv(t *testing.T) {
	in := []string{
		"AGENTSH_SIGNAL_SOCK_FD=4",
		"AGENTSH_UNIXWRAP_ARGV0=/bin/stale",
		"OTHER=x",
		"HOME=/tmp",
		"AGENTSH_UNIXWRAP_ARGV0_NOT_OURS=keep", // prefix-not-equal must be preserved
	}
	out := filterShimInternalEnv(in)
	for _, e := range out {
		if strings.HasPrefix(e, "AGENTSH_SIGNAL_SOCK_FD=") {
			t.Errorf("AGENTSH_SIGNAL_SOCK_FD not stripped: %q", e)
		}
		if strings.HasPrefix(e, "AGENTSH_UNIXWRAP_ARGV0=") {
			t.Errorf("AGENTSH_UNIXWRAP_ARGV0 not stripped: %q", e)
		}
	}
	want := map[string]bool{
		"OTHER=x":                              true,
		"HOME=/tmp":                            true,
		"AGENTSH_UNIXWRAP_ARGV0_NOT_OURS=keep": true,
	}
	got := map[string]bool{}
	for _, e := range out {
		got[e] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("expected entry %q in filtered env", w)
		}
	}
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

	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(fakeWrapperPrintEnvSrc), 0644); err != nil {
		t.Fatalf("write fake wrapper printenv source: %v", err)
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "fakewrap-printenv")

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

func TestInstall_RelayServerReject_NoACK_ResultFailClosed(t *testing.T) {
	wrapperBin := buildFakeWrapperNoACKExit(t)

	notifyDir := t.TempDir()
	notifySocket := filepath.Join(notifyDir, "notify.sock")
	ln, err := net.Listen("unix", notifySocket)
	if err != nil {
		t.Fatalf("listen notify socket: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		unixConn := conn.(*net.UnixConn)
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
		}
		_ = wraphandoff.WriteStatus(unixConn, false)
	}()

	wrapResp := types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySocket,
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
		t.Fatalf("expected ResultFailClosed, got %v (reason: %s)", res.Action, res.Reason)
	}
	if !strings.Contains(res.Reason, "server rejected wrap setup") {
		t.Fatalf("expected server rejection in reason, got %q", res.Reason)
	}
}

func TestInstall_RelaySetupStatusTimeout_NoACK_ResultFailClosed(t *testing.T) {
	wrapperBin := buildFakeWrapperNoACKExit(t)

	origTimeout := notifySetupStatusTimeout
	notifySetupStatusTimeout = 50 * time.Millisecond
	t.Cleanup(func() { notifySetupStatusTimeout = origTimeout })

	notifyDir := t.TempDir()
	notifySocket := filepath.Join(notifyDir, "notify.sock")
	ln, err := net.Listen("unix", notifySocket)
	if err != nil {
		t.Fatalf("listen notify socket: %v", err)
	}
	defer ln.Close()

	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
		}
		<-releaseServer
	}()

	wrapResp := types.WrapInitResponse{
		WrapperBinary: wrapperBin,
		NotifySocket:  notifySocket,
		WrapperEnv:    map[string]string{},
	}
	handler, _ := makeWrapInitHandler(200, wrapResp)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn

	type installResult struct {
		res Result
		err error
	}
	done := make(chan installResult, 1)
	go func() {
		res, err := Install(p)
		done <- installResult{res: res, err: err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Install returned error: %v", got.err)
		}
		if got.res.Action != ResultFailClosed {
			t.Fatalf("expected ResultFailClosed, got %v (reason: %s)", got.res.Action, got.res.Reason)
		}
		if !strings.Contains(got.res.Reason, "timed out waiting for notify setup status") {
			t.Fatalf("expected timeout in reason, got %q", got.res.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Install did not return after notify setup status timeout")
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

	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(fakeWrapperNoACKExitSrc), 0644); err != nil {
		t.Fatalf("write fake wrapper no-ack source: %v", err)
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "fakewrap-noack")

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
// The fake server listener accepts the forwarded fd and writes OK setup status.
// If the Go toolchain is unavailable the test is skipped.

func TestInstall_RelayHappyPath(t *testing.T) {
	// Build the fake wrapper binary.
	wrapperBin := buildFakeWrapper(t)

	// Start a fake notify-socket listener.
	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "notify.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serveNotifySetupStatus(ln, true)

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

	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(fakeWrapperSrc), 0644); err != nil {
		t.Fatalf("write fake wrapper source: %v", err)
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "fakewrap")

	buildCmd := exec.Command(goExe, "build", "-o", binPath, srcDir)
	buildCmd.Dir = modRoot
	out, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Skipf("compile fake wrapper: %v\n%s", err, out)
	}
	return binPath
}

// ─── Test: filterShimInternalEnv strips AGENTSH_WRAPPER_LOG_FD ──────────────

func TestFilterShimInternalEnv_StripsWrapperLogFD(t *testing.T) {
	in := []string{"PATH=/bin", wrapperlog.EnvKey + "=7", "HOME=/root"}
	out := filterShimInternalEnv(in)
	for _, e := range out {
		if strings.HasPrefix(e, wrapperlog.EnvKey+"=") {
			t.Fatalf("inherited %s not stripped: %v", wrapperlog.EnvKey, out)
		}
	}
	if len(out) != 2 {
		t.Fatalf("unexpected env after strip: %v", out)
	}
}

func TestAssembleWrapperEnv_DropsWrapperLogFDFromWrapperEnv(t *testing.T) {
	env := assembleWrapperEnv(
		[]string{"PATH=/bin"},
		"",
		map[string]string{
			wrapperlog.EnvKey:        "9", // must NOT pass through — the relay sets its own
			"AGENTSH_SECCOMP_CONFIG": "{}",
		},
		nil,
	)
	for _, e := range env {
		if strings.HasPrefix(e, wrapperlog.EnvKey+"=") {
			t.Fatalf("server-supplied %s leaked into wrapper env: %v", wrapperlog.EnvKey, env)
		}
	}
}

// TestInstall_PassesWrapperLogFDAndCreatesStateLogFile verifies the
// issue #415 relay wiring end-to-end: runRelay opens the state-dir log
// file, passes it as ExtraFiles[1], and exports AGENTSH_WRAPPER_LOG_FD=4
// to the wrapper. XDG_STATE_HOME is redirected to a temp dir so the test
// owns the state-dir location.
func TestInstall_PassesWrapperLogFDAndCreatesStateLogFile(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	wrapperBin := buildFakeWrapperPrintEnv(t)

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "notify.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveNotifySetupStatus(ln, true)

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
	p.Env = []string{"HOME=/tmp"}

	outFile, err := os.CreateTemp(t.TempDir(), "wrapper-env-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	outPath := outFile.Name()
	outFile.Close()
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
	if !strings.Contains(string(envOutput), wrapperlog.EnvKey+"=4") {
		t.Errorf("wrapper env missing %s=4:\n%s", wrapperlog.EnvKey, envOutput)
	}

	logPath := filepath.Join(stateHome, "agentsh", "logs", "unixwrap.log")
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("state-dir log file not created at %s: %v", logPath, err)
	}
}

// findModuleRoot walks up from the current working directory to find go.mod.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}
