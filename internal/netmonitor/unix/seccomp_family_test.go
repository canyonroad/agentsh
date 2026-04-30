//go:build linux && cgo

package unix

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	gounix "golang.org/x/sys/unix"
)

// familyHelperEnv gates the re-exec body inside the family block tests.
// Setting it outside of those tests' parent→child dispatch is unsupported.
const familyHelperEnv = "AGENTSH_TEST_FAMILY_HELPER"

// TestSeccompFamilyBlock_Errno verifies that installing a filter with
// BlockedFamilies = [{AF_ALG, errno}] causes socket(AF_ALG, ...) to return
// EAFNOSUPPORT in the process running with that filter.
//
// The test re-execs itself as a helper subprocess (keyed by familyHelperEnv)
// that installs the filter and calls socket(AF_ALG) via a raw syscall,
// printing the result. This isolates filter installation to the subprocess
// so the test runner's own filter is not affected.
func TestSeccompFamilyBlock_Errno(t *testing.T) {
	if os.Getenv(familyHelperEnv) == familyHelperErrno {
		runFamilyHelperErrno(t)
		return
	}

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^TestSeccompFamilyBlock_Errno$", "-test.v")
	cmd.Env = append(os.Environ(), familyHelperEnv+"="+familyHelperErrno)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "lacks user notify") {
			t.Skipf("host cannot install seccomp filter; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("helper subprocess failed: %v\noutput:\n%s", runErr, combined)
	}

	if !strings.Contains(combined, "socket_result=EAFNOSUPPORT") &&
		!strings.Contains(combined, "socket_result=address family not supported") &&
		!strings.Contains(combined, "errno=97") {
		t.Errorf("expected socket(AF_ALG) to return EAFNOSUPPORT (errno 97); helper output:\n%s", combined)
	}
}

// runFamilyHelperErrno is the subprocess body for TestSeccompFamilyBlock_Errno.
// It installs the filter and performs a raw socket(AF_ALG) syscall,
// printing the errno so the parent can assert the correct result.
func runFamilyHelperErrno(t *testing.T) {
	t.Helper()
	cfg := FilterConfig{
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockErrno, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	// Raw syscall so the filter interception is visible at the syscall level.
	fd, _, errno := gounix.RawSyscall(gounix.SYS_SOCKET, gounix.AF_ALG, gounix.SOCK_SEQPACKET, 0)
	if fd != ^uintptr(0) {
		// Unexpectedly got a valid fd — close it.
		_ = gounix.Close(int(fd))
		fmt.Printf("socket_result=OK (expected EAFNOSUPPORT)\n")
		return
	}
	// Print both the numeric errno and the stringer form so the parent
	// can match either. EAFNOSUPPORT=97 on Linux/amd64.
	fmt.Printf("socket_result=%v (errno=%d)\n", errno, int(errno))
}

// TestSeccompFamilyBlock_Map_Errno verifies that BlockedFamilyMap is empty
// for errno-action families (they use ActErrno, not notify — no dispatch needed).
func TestSeccompFamilyBlock_Map_Errno(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockErrno, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	if len(m) != 0 {
		t.Errorf("errno-action families must not populate BlockedFamilyMap; got %v", m)
	}
}

// TestSeccompFamilyBlock_Map_Log verifies that log-action families populate
// BlockedFamilyMap with keys for both SYS_SOCKET and SYS_SOCKETPAIR.
func TestSeccompFamilyBlock_Map_Log(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockLog, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	socketKey := uint64(gounix.SYS_SOCKET)<<32 | uint64(gounix.AF_ALG)
	socketpairKey := uint64(gounix.SYS_SOCKETPAIR)<<32 | uint64(gounix.AF_ALG)

	if _, ok := m[socketKey]; !ok {
		t.Errorf("BlockedFamilyMap missing SYS_SOCKET|AF_ALG key; map: %v", m)
	}
	if _, ok := m[socketpairKey]; !ok {
		t.Errorf("BlockedFamilyMap missing SYS_SOCKETPAIR|AF_ALG key; map: %v", m)
	}
	if len(m) != 2 {
		t.Errorf("expected exactly 2 map entries (socket+socketpair for AF_ALG); got %d: %v", len(m), m)
	}
	if m[socketKey].Name != "AF_ALG" {
		t.Errorf("map entry name=%q, want AF_ALG", m[socketKey].Name)
	}
}

// TestSeccompFamilyBlock_Map_LogAndKill verifies that log_and_kill-action families
// also populate BlockedFamilyMap (same dispatch path as log).
func TestSeccompFamilyBlock_Map_LogAndKill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockLogAndKill, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	if len(m) != 2 {
		t.Errorf("log_and_kill must populate BlockedFamilyMap; got %d entries: %v", len(m), m)
	}
}

// TestSeccompFamilyBlock_Map_Kill verifies that kill-action families do NOT
// populate BlockedFamilyMap (ActKillProcess, no notify path needed).
func TestSeccompFamilyBlock_Map_Kill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockKill, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	if len(m) != 0 {
		t.Errorf("kill-action families must not populate BlockedFamilyMap; got %v", m)
	}
}

// TestSeccompFamilyBlock_Coexistence verifies Section B of the plan:
// with UnixSocketEnabled=true AND BlockedFamilies=[{AF_ALG, errno}],
// an AF_ALG socket returns EAFNOSUPPORT (errno path takes precedence
// over the unconditional ActNotify for socket(2) via libseccomp's
// action-precedence: ERRNO > NOTIFY).
//
// This test installs the filter in-process since it only checks the
// map state, not actual socket calls (which would trap the test runner).
func TestSeccompFamilyBlock_Coexistence_MapState(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockErrno, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	// The filter should have installed successfully. The important
	// invariant is that BlockedFamilyMap is empty (errno uses ActErrno,
	// not notify) and the notify fd is valid (UnixSocketEnabled).
	m := filt.BlockedFamilyMap()
	if len(m) != 0 {
		t.Errorf("errno-action family must not populate notify dispatch map; got %v", m)
	}
	if filt.NotifFD() < 0 {
		t.Errorf("UnixSocketEnabled=true should produce valid notify fd; got %d", filt.NotifFD())
	}
}

// TestFamilyToScmpAction verifies the helper maps actions to the
// correct libseccomp actions without requiring filter installation.
func TestFamilyToScmpAction(t *testing.T) {
	cases := []struct {
		action  seccompkg.OnBlockAction
		wantErr bool
	}{
		{seccompkg.OnBlockErrno, false},
		{seccompkg.OnBlockKill, false},
		{seccompkg.OnBlockLog, false},
		{seccompkg.OnBlockLogAndKill, false},
		{seccompkg.OnBlockAction("bogus"), true},
	}
	for _, c := range cases {
		_, err := familyToScmpAction(c.action)
		if (err != nil) != c.wantErr {
			t.Errorf("familyToScmpAction(%q): err=%v wantErr=%v", c.action, err, c.wantErr)
		}
	}
}

// TestFamilyDispatchBeforeGenericBlocklist_Unit is a unit-level guard for the
// dispatch ordering fix: when both a generic blocklist entry for socket(2) AND
// a more-specific family entry for AF_ALG are configured, FamilyBlockListed
// must return true (and thus win) before IsBlockListed is consulted.
//
// This does NOT need real seccomp — it exercises only the BlockListConfig
// lookup methods to prove the dispatch branching in ServeNotifyWithExecve is
// correct by construction.
func TestFamilyDispatchBeforeGenericBlocklist_Unit(t *testing.T) {
	genericAction := seccompkg.OnBlockLog       // generic socket action
	familyAction := seccompkg.OnBlockLogAndKill // more-specific AF_ALG action

	bl := &BlockListConfig{
		// Generic blocklist: socket(2) → log
		ActionByNr: map[uint32]seccompkg.OnBlockAction{
			uint32(gounix.SYS_SOCKET): genericAction,
		},
		// Family blocklist: (socket, AF_ALG) → log_and_kill
		FamilyByKey: map[uint64]seccompkg.BlockedFamily{
			uint64(gounix.SYS_SOCKET)<<32 | uint64(gounix.AF_ALG): {
				Family: gounix.AF_ALG,
				Action: familyAction,
				Name:   "AF_ALG",
			},
		},
	}

	// For SYS_SOCKET + AF_ALG: family check should match (and would win).
	bf, familyMatched := bl.FamilyBlockListed(uint32(gounix.SYS_SOCKET), uint64(gounix.AF_ALG))
	if !familyMatched {
		t.Fatal("FamilyBlockListed should match for (SYS_SOCKET, AF_ALG)")
	}
	if bf.Action != familyAction {
		t.Errorf("family action = %q; want %q", bf.Action, familyAction)
	}

	// Generic check also matches — but dispatch order means family checked first.
	_, genericMatched := bl.IsBlockListed(uint32(gounix.SYS_SOCKET))
	if !genericMatched {
		t.Fatal("IsBlockListed should also match for SYS_SOCKET (sanity check)")
	}

	// For SYS_SOCKET + AF_INET: family check should NOT match; generic should.
	_, familyMatchedInet := bl.FamilyBlockListed(uint32(gounix.SYS_SOCKET), uint64(gounix.AF_INET))
	if familyMatchedInet {
		t.Error("FamilyBlockListed should NOT match for (SYS_SOCKET, AF_INET)")
	}
	_, genericMatchedInet := bl.IsBlockListed(uint32(gounix.SYS_SOCKET))
	if !genericMatchedInet {
		t.Error("IsBlockListed should match for SYS_SOCKET even for non-blocked family")
	}
}

const familyHelperErrno = "errno"
const familyHelperNotifyLog = "notify_log"
const familyHelperFamilyWinsOverBlocklist = "family_wins_over_blocklist"

// TestSeccompFamilyBlock_Notify_LogDispatched verifies that when a filter is
// installed with BlockedFamilies=[{AF_ALG, log}] and UnixSocketEnabled=false,
// socket(AF_ALG) dispatches through the notify handler and returns EAFNOSUPPORT,
// and that a seccomp_socket_family_blocked audit event is emitted.
//
// The test re-execs itself as a helper subprocess that installs the filter,
// starts the notify handler, and performs a raw socket(AF_ALG) syscall.
// Skip if insufficient privileges.
func TestSeccompFamilyBlock_Notify_LogDispatched(t *testing.T) {
	if os.Getenv(familyHelperEnv) == familyHelperNotifyLog {
		runFamilyHelperNotifyLog(t)
		return
	}

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^TestSeccompFamilyBlock_Notify_LogDispatched$", "-test.v")
	cmd.Env = append(os.Environ(), familyHelperEnv+"="+familyHelperNotifyLog)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	// Check for an explicit skip sentinel first — t.Skipf in the child exits
	// status 0, so runErr is nil even when the child skipped. Without this
	// check the parent would continue to assertions on empty output and fail.
	if strings.Contains(combined, "SKIP:") {
		t.Skipf("child skipped: %s", combined)
	}

	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "lacks user notify") ||
			strings.Contains(lower, "skip") {
			t.Skipf("host cannot install seccomp filter; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("helper subprocess failed: %v\noutput:\n%s", runErr, combined)
	}

	if !strings.Contains(combined, "socket_result=EAFNOSUPPORT") &&
		!strings.Contains(combined, "socket_result=address family not supported") &&
		!strings.Contains(combined, "errno=97") {
		t.Errorf("expected socket(AF_ALG) to return EAFNOSUPPORT via notify handler; helper output:\n%s", combined)
	}
	if !strings.Contains(combined, "audit_event=seccomp_socket_family_blocked") {
		t.Errorf("expected seccomp_socket_family_blocked audit event; helper output:\n%s", combined)
	}
}

// runFamilyHelperNotifyLog is the subprocess body for TestSeccompFamilyBlock_Notify_LogDispatched.
// It installs the filter with log action, runs the notify handler, performs a
// raw socket(AF_ALG) call, and prints the result and audit event type.
func runFamilyHelperNotifyLog(t *testing.T) {
	t.Helper()

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	cfg := FilterConfig{
		UnixSocketEnabled: false,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockLog, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "permission") || strings.Contains(lower, "operation not permitted") {
			t.Skipf("cannot install seccomp filter (privilege): %v", err)
		}
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	notifFD := filt.NotifFD()
	if notifFD < 0 {
		t.Fatalf("expected valid notify fd; got %d", notifFD)
	}

	// Build a BlockListConfig carrying the family map.
	familyByKey := filt.BlockedFamilyMap()
	if len(familyByKey) == 0 {
		t.Fatalf("BlockedFamilyMap is empty; log action should populate it")
	}
	bl := &BlockListConfig{FamilyByKey: familyByKey}

	// Collect emitted events.
	type capturedEvent struct{ typ string }
	var (
		mu     sync.Mutex
		events []capturedEvent
	)
	emitter := &captureEmitter{fn: func(typ string) {
		mu.Lock()
		events = append(events, capturedEvent{typ: typ})
		mu.Unlock()
	}}

	// Run the notify handler in background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifyFile := os.NewFile(uintptr(notifFD), "seccomp-notify")
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		ServeNotifyWithExecve(ctx, notifyFile, "test-family-notify", nil, emitter, nil, nil, bl)
	}()

	// Perform the blocked socket call.
	fd, _, errno := gounix.RawSyscall(gounix.SYS_SOCKET, gounix.AF_ALG, gounix.SOCK_SEQPACKET, 0)
	if fd != ^uintptr(0) {
		_ = gounix.Close(int(fd))
		fmt.Printf("socket_result=OK (expected EAFNOSUPPORT)\n")
	} else {
		fmt.Printf("socket_result=%v (errno=%d)\n", errno, int(errno))
	}

	// Cancel and wait for handler to exit.
	cancel()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		fmt.Printf("handler did not exit in time\n")
	}

	// Report emitted events.
	mu.Lock()
	defer mu.Unlock()
	for _, ev := range events {
		fmt.Printf("audit_event=%s\n", ev.typ)
	}
}

// captureEmitter records the Type field of every emitted event.
type captureEmitter struct {
	fn func(typ string)
}

func (e *captureEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	if e.fn != nil {
		e.fn(ev.Type)
	}
	return nil
}
func (e *captureEmitter) Publish(ev types.Event) {
	if e.fn != nil {
		e.fn(ev.Type)
	}
}

// TestFamilyDispatchBeforeGenericBlocklist verifies the dispatch ordering fix:
// when a filter has socket(2) in the generic syscall blocklist (on_block=log) AND
// AF_ALG in blocked_socket_families (action=log — so the process is NOT killed and
// can print the audit event), the family-specific event type must win.
//
// The key assertion: audit event type is seccomp_socket_family_blocked, NOT
// seccomp_blocked.
//
// The test re-execs itself as a helper subprocess. Skip if the host cannot
// install a seccomp notify filter.
func TestFamilyDispatchBeforeGenericBlocklist(t *testing.T) {
	if os.Getenv(familyHelperEnv) == familyHelperFamilyWinsOverBlocklist {
		runFamilyHelperFamilyWinsOverBlocklist(t)
		return
	}

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^TestFamilyDispatchBeforeGenericBlocklist$", "-test.v")
	cmd.Env = append(os.Environ(), familyHelperEnv+"="+familyHelperFamilyWinsOverBlocklist)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	// Check for an explicit skip sentinel first — t.Skipf in the child exits
	// status 0, so runErr is nil even when the child skipped. Without this
	// check the parent would continue to assertions on empty output and fail.
	if strings.Contains(combined, "SKIP:") {
		t.Skipf("child skipped: %s", combined)
	}

	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "lacks user notify") ||
			strings.Contains(lower, "skip") {
			t.Skipf("host cannot install seccomp filter; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("helper subprocess failed: %v\noutput:\n%s", runErr, combined)
	}

	// Family action must win: audit event is socket_family_blocked, not syscall_blocked.
	if !strings.Contains(combined, "audit_event=seccomp_socket_family_blocked") {
		t.Errorf("expected seccomp_socket_family_blocked audit event (family action must win);\nhelper output:\n%s", combined)
	}
	if strings.Contains(combined, "audit_event=seccomp_blocked") {
		t.Errorf("seccomp_blocked event emitted — generic blocklist shadowed family action;\nhelper output:\n%s", combined)
	}
}

// runFamilyHelperFamilyWinsOverBlocklist is the subprocess body for
// TestFamilyDispatchBeforeGenericBlocklist. It installs a filter that has:
//   - socket(2) in the generic syscall blocklist (on_block=log → notify path)
//   - AF_ALG in the blocked-family map with action=log (notify path, no kill)
//
// Using log (not log_and_kill) for the family action so the process is not
// killed and can emit the audit event before printing. The test parent verifies
// that the emitted audit event is seccomp_socket_family_blocked, not
// seccomp_blocked.
func runFamilyHelperFamilyWinsOverBlocklist(t *testing.T) {
	t.Helper()

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	// Install a filter with both a generic socket blocklist entry (log) AND a
	// family-specific entry for AF_ALG (also log, so the process is not killed
	// and can print results). The family action must win (event type check).
	cfg := FilterConfig{
		UnixSocketEnabled: false,
		BlockedSyscalls:   []int{int(gounix.SYS_SOCKET)},
		OnBlockAction:     seccompkg.OnBlockLog,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_ALG, Action: seccompkg.OnBlockLog, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "permission") || strings.Contains(lower, "operation not permitted") {
			t.Skipf("cannot install seccomp filter (privilege): %v", err)
		}
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	notifFD := filt.NotifFD()
	if notifFD < 0 {
		t.Fatalf("expected valid notify fd; got %d", notifFD)
	}

	// Build BlockListConfig with both the generic socket action AND the family map.
	familyByKey := filt.BlockedFamilyMap()
	if len(familyByKey) == 0 {
		t.Fatalf("BlockedFamilyMap is empty; log family should populate it")
	}
	bl := &BlockListConfig{
		ActionByNr:  filt.BlockListMap(),
		FamilyByKey: familyByKey,
	}
	if len(bl.ActionByNr) == 0 {
		t.Fatalf("BlockListMap is empty; log action on socket should populate it")
	}

	// Collect emitted events.
	var (
		mu     sync.Mutex
		events []string
	)
	emitter := &captureEmitter{fn: func(typ string) {
		mu.Lock()
		events = append(events, typ)
		mu.Unlock()
	}}

	// Run the notify handler in background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifyFile := os.NewFile(uintptr(notifFD), "seccomp-notify")
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		ServeNotifyWithExecve(ctx, notifyFile, "test-family-dispatch-order", nil, emitter, nil, nil, bl)
	}()

	// Perform the blocked socket call.
	fd, _, errno := gounix.RawSyscall(gounix.SYS_SOCKET, gounix.AF_ALG, gounix.SOCK_SEQPACKET, 0)
	if fd != ^uintptr(0) {
		_ = gounix.Close(int(fd))
		fmt.Printf("socket_result=OK\n")
	} else {
		fmt.Printf("socket_result=%v (errno=%d)\n", errno, int(errno))
	}

	// Cancel and wait for handler to exit.
	cancel()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		fmt.Printf("handler did not exit in time\n")
	}

	// Report emitted events so the parent can assert dispatch routing.
	mu.Lock()
	defer mu.Unlock()
	for _, ev := range events {
		fmt.Printf("audit_event=%s\n", ev)
	}
}
