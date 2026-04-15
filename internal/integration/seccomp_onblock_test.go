//go:build integration && linux

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// ---------- Helper Binary (self re-exec) ----------

// TestMain switches the binary into "helper mode" when GO_WANT_HELPER_PROCESS=1
// is set, before any testing framework scheduling. Helper logic runs on the
// main OS thread, which is also the thread-group leader (TGL) of the helper
// process. Scenarios that exercise multi-threaded behavior fire ptrace from
// non-TGL goroutines — the production handler must resolve TID→TGID before
// pidfd_open for those to get SIGKILL'd.
func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		runHelper()
		return
	}
	os.Exit(m.Run())
}

// runHelper executes the blocked-syscall scenario named by the trailing CLI
// argument after "--". Exits the process directly rather than returning, so
// the Go test framework never gets a chance to run real tests in the child.
func runHelper() {
	args := os.Args
	var mode string
	for i, a := range args {
		if a == "--" && i+1 < len(args) {
			mode = args[i+1]
			break
		}
	}
	switch mode {
	case "ptrace-traceme":
		// Call the raw ptrace syscall: PTRACE_TRACEME has no args.
		// Returns EPERM under errno/log modes; kills us under kill/log_and_kill.
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
		if errno == unix.EPERM {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "ptrace-traceme: unexpected errno=%d\n", errno)
		os.Exit(1)
	case "ptrace-storm":
		// Fire ptrace from 100 non-TGL goroutines. Each goroutine pins to its
		// own OS thread (via LockOSThread) so its TID is guaranteed to differ
		// from TGID, exercising the TGID-resolution path in the handler. The
		// main thread never fires ptrace — this makes the test fail loudly if
		// production ever regresses to pidfd_open(TID) without TGID lookup.
		const n = 100
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				runtime.LockOSThread()
				defer wg.Done()
				for j := 0; j < 5; j++ {
					_, _, _ = unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
				}
			}()
		}
		wg.Wait()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode: %q\n", mode)
		os.Exit(2)
	}
}

// ---------- Build Cache ----------

var (
	unixwrapBuildOnce sync.Once
	unixwrapBuildPath string
	unixwrapBuildErr  error
)

// buildUnixwrapOnce builds agentsh-unixwrap once per test process and returns
// the cached path. All on_block tests share the same binary; rebuilding per
// test is wasteful.
func buildUnixwrapOnce(t *testing.T) string {
	t.Helper()
	unixwrapBuildOnce.Do(func() {
		tempDir, err := os.MkdirTemp("", "agentsh-unixwrap-build-")
		if err != nil {
			unixwrapBuildErr = fmt.Errorf("mkdtemp: %w", err)
			return
		}
		out := filepath.Join(tempDir, "agentsh-unixwrap")

		wd, err := os.Getwd()
		if err != nil {
			unixwrapBuildErr = fmt.Errorf("getwd: %w", err)
			return
		}
		repoRoot := wd
		for {
			if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err == nil {
				break
			}
			next := filepath.Dir(repoRoot)
			if next == repoRoot {
				unixwrapBuildErr = fmt.Errorf("go.mod not found")
				return
			}
			repoRoot = next
		}

		cmd := exec.Command("go", "build", "-o", out, "./cmd/agentsh-unixwrap")
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			unixwrapBuildErr = fmt.Errorf("go build agentsh-unixwrap: %w", err)
			return
		}
		unixwrapBuildPath = out
	})
	if unixwrapBuildErr != nil {
		t.Fatalf("build agentsh-unixwrap: %v", unixwrapBuildErr)
	}
	return unixwrapBuildPath
}

// ---------- Recording Emitter ----------

// recordingEmitter captures every event the notify handler publishes. Safe
// for concurrent use by a single writer (the handler goroutine) and the test
// goroutine reading after the handler exits.
type recordingEmitter struct {
	mu     sync.Mutex
	events []types.Event
}

func (r *recordingEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	return nil
}

func (r *recordingEmitter) Publish(_ types.Event) {}

func (r *recordingEmitter) snapshot() []types.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]types.Event, len(r.events))
	copy(out, r.events)
	return out
}

// ---------- Block-list config builder ----------

// buildBlockListFromCfgJSON mirrors api.buildBlockListConfigFor so the notify
// handler receives the same dispatch map in tests as in production.
func buildBlockListFromCfgJSON(t *testing.T, cfgJSON string) *unixmon.BlockListConfig {
	t.Helper()
	var cfg struct {
		BlockedSyscalls []string `json:"blocked_syscalls"`
		OnBlock         string   `json:"on_block"`
	}
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("parse cfgJSON: %v", err)
	}
	bl := &unixmon.BlockListConfig{}
	action, ok := seccompkg.ParseOnBlock(cfg.OnBlock)
	if !ok {
		return bl
	}
	if action != seccompkg.OnBlockLog && action != seccompkg.OnBlockLogAndKill {
		return bl
	}
	nrs, _ := seccompkg.ResolveSyscalls(cfg.BlockedSyscalls)
	bl.ActionByNr = make(map[uint32]seccompkg.OnBlockAction, len(nrs))
	for _, nr := range nrs {
		bl.ActionByNr[uint32(nr)] = action
	}
	return bl
}

// ---------- startWrappedChild ----------

// startWrappedChild spawns agentsh-unixwrap with the given config JSON, execs
// the in-package test helper (/proc/self/exe with GO_WANT_HELPER_PROCESS=1)
// and waits for it to exit. For log/log_and_kill modes it also runs the
// seccomp notify dispatcher in a goroutine and returns the events it emitted.
//
// For errno/kill modes the wrapper installs a kernel-side filter (no
// ActNotify rule), so no notify fd is created and no handler runs — events
// will be nil in those cases, matching production.
func startWrappedChild(t *testing.T, cfgJSON string, cmdArg string) (syscall.WaitStatus, []types.Event, error) {
	t.Helper()

	wrap := buildUnixwrapOnce(t)
	bl := buildBlockListFromCfgJSON(t, cfgJSON)
	hasNotify := bl != nil && len(bl.ActionByNr) > 0

	// socketpair for notify fd handoff (only meaningful in log/log_and_kill).
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("socketpair: %w", err)
	}
	parentFD := sp[0]
	childFD := sp[1]
	// childEnd will be dup'd into the wrapper via ExtraFiles (fd 3); we close
	// our copy immediately after start. parentEnd stays open for the duration.
	defer unix.Close(parentFD)
	childEnd := os.NewFile(uintptr(childFD), "child-end")
	// Note: passing via ExtraFiles causes Go to dup-and-clexec. We keep
	// childEnd alive until after cmd.Start so the fd survives the fork.
	defer childEnd.Close()

	// Re-exec the test binary as the target (instead of an external binary).
	// With GO_WANT_HELPER_PROCESS=1 the wrapped test switches to helper mode.
	testBin, err := os.Executable()
	if err != nil {
		return 0, nil, fmt.Errorf("os.Executable: %w", err)
	}

	args := []string{
		"--",
		testBin,
		"--",
		cmdArg,
	}
	cmd := exec.Command(wrap, args...)
	cmd.ExtraFiles = []*os.File{childEnd}
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"AGENTSH_NOTIFY_SOCK_FD=3",
		"AGENTSH_SECCOMP_CONFIG="+cfgJSON,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, nil, fmt.Errorf("start wrapper: %w", err)
	}

	emitter := &recordingEmitter{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var serveDone chan struct{}
	var notifyFile *os.File
	if hasNotify {
		// Receive the notify fd from the wrapper.
		parentEnd := os.NewFile(uintptr(parentFD), "parent-end")
		// parentEnd shares the fd with parentFD; do NOT double-close.
		recvd, rerr := unixmon.RecvFD(parentEnd)
		if rerr != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return 0, nil, fmt.Errorf("RecvFD: %w", rerr)
		}
		notifyFile = recvd

		// ACK so the wrapper proceeds to exec.
		if _, werr := unix.Write(parentFD, []byte{1}); werr != nil {
			_ = notifyFile.Close()
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return 0, nil, fmt.Errorf("ACK: %w", werr)
		}

		serveDone = make(chan struct{})
		go func() {
			defer close(serveDone)
			unixmon.ServeNotifyWithExecve(ctx, notifyFile, "test-session", nil, emitter, nil, nil, bl)
		}()
	}

	waitErr := cmd.Wait()
	// Treat non-exit errors as real errors; ExitError is expected when the
	// child is signalled — we surface status via WaitStatus regardless.
	var exitErr *exec.ExitError
	if waitErr != nil {
		if asExit, ok := waitErr.(*exec.ExitError); ok {
			exitErr = asExit
			waitErr = nil
		}
	}
	var status syscall.WaitStatus
	if exitErr != nil {
		status = exitErr.ProcessState.Sys().(syscall.WaitStatus)
	} else if cmd.ProcessState != nil {
		status = cmd.ProcessState.Sys().(syscall.WaitStatus)
	}

	// Shut the notify loop down and close our notify fd copy so any remaining
	// receive returns an error and the goroutine exits promptly.
	cancel()
	if notifyFile != nil {
		_ = notifyFile.Close()
	}
	if serveDone != nil {
		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
			// Loop didn't exit — leak but don't fail; surface in log.
			t.Logf("warning: ServeNotifyWithExecve did not exit within 2s")
		}
	}

	return status, emitter.snapshot(), waitErr
}

// ---------- Tests ----------

func TestSeccompOnBlock_Errno(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "errno"
	}`
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Exited())
	require.Equal(t, 0, st.ExitStatus(), "child should see EPERM and exit 0")
	require.Empty(t, events, "errno mode must not emit seccomp_blocked events")
}

func TestSeccompOnBlock_Kill(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "kill"
	}`
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Signaled(), "child should die by signal")
	require.Equal(t, syscall.SIGSYS, st.Signal(), "kill mode uses SCMP_ACT_KILL_PROCESS which delivers SIGSYS")
	require.Empty(t, events, "kill mode must not emit seccomp_blocked events")
}

func TestSeccompOnBlock_Log(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log"
	}`
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Exited())
	require.Equal(t, 0, st.ExitStatus(), "log mode returns EPERM; child exits normally")
	require.Len(t, events, 1, "log mode must emit exactly one seccomp_blocked event")
	ev := events[0]
	require.Equal(t, "seccomp_blocked", ev.Type)
	require.Equal(t, "ptrace", ev.Fields["syscall"])
	require.Equal(t, "denied", ev.Fields["outcome"])
	require.Equal(t, "log", ev.Fields["action"])
}

func TestSeccompOnBlock_LogAndKill(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log_and_kill"
	}`
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Signaled(), "log_and_kill must kill the child")
	require.Equal(t, syscall.SIGKILL, st.Signal(), "pidfd_send_signal delivers SIGKILL")
	require.Len(t, events, 1)
	ev := events[0]
	require.Equal(t, "seccomp_blocked", ev.Type)
	require.Equal(t, "ptrace", ev.Fields["syscall"])
	require.Equal(t, "log_and_kill", ev.Fields["action"])
	require.Equal(t, "killed", ev.Fields["outcome"])
}

func TestSeccompOnBlock_LogAndKill_ConcurrentCalls(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log_and_kill"
	}`
	done := make(chan struct{})
	var st syscall.WaitStatus
	var events []types.Event
	var err error
	go func() {
		st, events, err = startWrappedChild(t, cfgJSON, "ptrace-storm")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("child did not exit within 10s — possible handler deadlock")
	}
	require.NoError(t, err)
	require.True(t, st.Signaled())
	require.Equal(t, syscall.SIGKILL, st.Signal())
	// Expect >=1 event, and at least one tagged outcome=killed.
	//
	// Exact count is racy by construction: 100 goroutines each fire 5 ptrace
	// syscalls, all from non-TGL threads. The kernel queues multiple notifs
	// before the first SIGKILL lands; the handler processes each one, resolves
	// its TGID via /proc/<tid>/status, and (for notifs whose id is still
	// valid) sends SIGKILL again. Notifs that arrive after the process is
	// reaped fail NotifIDValid with ENOENT — the handler returns early and
	// emits no event. So we land somewhere between 1 and a handful of events.
	//
	// The critical invariant is that at least one event records
	// outcome=killed: that proves the TID→TGID resolution seam worked for a
	// notification from a non-leader thread. A pre-fix handler (pidfd_open on
	// raw TID) would see ENOENT on kernel 6.8, emit outcome=denied, and never
	// deliver SIGKILL — the child would continue spinning on ptrace rather
	// than dying by signal, and st.Signaled() would be false.
	require.GreaterOrEqual(t, len(events), 1, "at least one seccomp_blocked event expected")
	sawKilled := false
	for _, ev := range events {
		if ev.Fields["outcome"] == "killed" {
			sawKilled = true
			break
		}
	}
	require.True(t, sawKilled, "at least one event must record outcome=killed (proves TGID resolution worked for a non-TGL thread)")
}

func TestSeccompOnBlock_DoesNotAffectFileMonitor(t *testing.T) {
	t.Skip("non-interference covered by other subsystem integration suites; block-list dispatch uses IsBlockListed over a fixed map of resolved syscall numbers and cannot intercept file_monitor syscalls")
}

func TestSeccompOnBlock_DoesNotAffectUnixSocket(t *testing.T) {
	t.Skip("non-interference covered by other subsystem integration suites; block-list dispatch uses IsBlockListed over a fixed map of resolved syscall numbers and cannot intercept unix socket syscalls")
}

func TestSeccompOnBlock_DoesNotAffectSignalFilter(t *testing.T) {
	t.Skip("non-interference covered by other subsystem integration suites; block-list dispatch uses IsBlockListed over a fixed map of resolved syscall numbers and cannot intercept signal filter syscalls")
}

func TestSeccompOnBlock_DefaultBlockListResolvesOnThisArch(t *testing.T) {
	defaults := []string{
		"ptrace", "process_vm_readv", "process_vm_writev",
		"personality", "mount", "umount2", "pivot_root",
		"reboot", "kexec_load", "init_module", "finit_module",
		"delete_module", "sethostname", "setdomainname",
	}
	resolved, skipped := seccompkg.ResolveSyscalls(defaults)
	require.Empty(t, skipped,
		"all default block-list syscalls must resolve on %s; skipped=%v",
		runtime.GOARCH, skipped)
	require.Len(t, resolved, len(defaults))
}
