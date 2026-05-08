//go:build linux && cgo

package unix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/agentsh/agentsh/internal/config"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

const socketRuleHelperEnv = "AGENTSH_TEST_SOCKET_RULE_HELPER"
const socketRuleHelperNotifyLog = "notify_log"
const socketRuleHelperDirtyFragNetlinkXFRM = "dirtyfrag_netlink_xfrm"
const socketRuleHelperDirtyFragNetlinkRoute = "dirtyfrag_netlink_route"
const socketRuleHelperDirtyFragRXRPC = "dirtyfrag_rxrpc"
const socketRuleHelperDirtyFragSocketpairXFRM = "dirtyfrag_socketpair_xfrm"

func TestNotifySocketRules_FiltersNotifyActions(t *testing.T) {
	rules := []seccompkg.SocketRule{
		{Name: "errno", Family: 60, Action: seccompkg.OnBlockErrno},
		{Name: "kill", Family: 61, Action: seccompkg.OnBlockKill},
		{Name: "log", Family: 62, Action: seccompkg.OnBlockLog},
		{Name: "log_and_kill", Family: 63, Action: seccompkg.OnBlockLogAndKill},
	}

	got := notifySocketRules(rules)

	require.Len(t, got, 2)
	require.Equal(t, "log", got[0].Name)
	require.Equal(t, "log_and_kill", got[1].Name)
}

func TestInstallFilterWithConfig_SocketRulesRetainedOnlyForNotifyActions(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	rules := []seccompkg.SocketRule{
		{Name: "errno", Family: 60, Action: seccompkg.OnBlockErrno},
		{Name: "kill", Family: 61, Action: seccompkg.OnBlockKill},
		{Name: "log", Family: 62, Action: seccompkg.OnBlockLog},
		{Name: "log_and_kill", Family: 63, Action: seccompkg.OnBlockLogAndKill},
	}

	filt, err := InstallFilterWithConfig(FilterConfig{SocketRules: rules})
	require.NoError(t, err)
	defer filt.Close()

	got := filt.SocketRules()
	require.Len(t, got, 2)
	require.Equal(t, "log", got[0].Name)
	require.Equal(t, "log_and_kill", got[1].Name)
}

func TestFilterSocketRules_ReturnsDeepCopy(t *testing.T) {
	typ := int(gounix.SOCK_DGRAM)
	protocol := int(gounix.NETLINK_XFRM)
	filt := &Filter{
		socketRules: []seccompkg.SocketRule{
			{
				Name:     "netlink_xfrm",
				Family:   gounix.AF_NETLINK,
				Type:     &typ,
				Protocol: &protocol,
				Action:   seccompkg.OnBlockLog,
			},
		},
	}

	got := filt.SocketRules()
	require.Len(t, got, 1)
	got[0].Name = "mutated"
	*got[0].Type = int(gounix.SOCK_RAW)
	*got[0].Protocol = int(gounix.NETLINK_AUDIT)

	again := filt.SocketRules()
	require.Equal(t, "netlink_xfrm", again[0].Name)
	require.Equal(t, int(gounix.SOCK_DGRAM), *again[0].Type)
	require.Equal(t, int(gounix.NETLINK_XFRM), *again[0].Protocol)
}

func TestSocketRules_RetainProtocolSpecificNetlinkXFRM(t *testing.T) {
	typ := int(gounix.SOCK_RAW)
	protocol := int(gounix.NETLINK_XFRM)
	got := notifySocketRules([]seccompkg.SocketRule{
		{
			Name:         "netlink_xfrm",
			Family:       gounix.AF_NETLINK,
			FamilyName:   "AF_NETLINK",
			Type:         &typ,
			TypeName:     "SOCK_RAW",
			Protocol:     &protocol,
			ProtocolName: "NETLINK_XFRM",
			Action:       seccompkg.OnBlockLog,
		},
	})

	require.Len(t, got, 1)
	require.Equal(t, gounix.AF_NETLINK, got[0].Family)
	require.NotNil(t, got[0].Protocol)
	require.Equal(t, int(gounix.NETLINK_XFRM), *got[0].Protocol)
}

func TestSocketRuleConditions_UseMaskedTypeAndProtocol(t *testing.T) {
	typ := int(gounix.SOCK_DGRAM)
	protocol := int(gounix.NETLINK_XFRM)
	rule := seccompkg.SocketRule{
		Family:   gounix.AF_NETLINK,
		Type:     &typ,
		Protocol: &protocol,
		Action:   seccompkg.OnBlockLog,
	}

	conds := socketRuleConditions(rule)

	require.Len(t, conds, 3)
	require.Equal(t, seccomp.ScmpCondition{
		Argument: 0,
		Op:       seccomp.CompareEqual,
		Operand1: uint64(gounix.AF_NETLINK),
	}, conds[0])
	require.Equal(t, seccomp.ScmpCondition{
		Argument: 1,
		Op:       seccomp.CompareMaskedEqual,
		Operand1: uint64(seccompkg.SocketTypeMask),
		Operand2: uint64(gounix.SOCK_DGRAM),
	}, conds[1])
	require.Equal(t, seccomp.ScmpCondition{
		Argument: 2,
		Op:       seccomp.CompareEqual,
		Operand1: uint64(gounix.NETLINK_XFRM),
	}, conds[2])
}

func TestInstallSocketRuleConditional_InstallsSocketpairProtocolRule(t *testing.T) {
	protocol := int(gounix.NETLINK_XFRM)
	rule := seccompkg.SocketRule{
		Family:   gounix.AF_NETLINK,
		Protocol: &protocol,
		Action:   seccompkg.OnBlockLog,
	}
	recorder := &recordingConditionalAdder{}

	added, err := installSocketRuleConditional(recorder, rule, seccomp.ActNotify)

	require.NoError(t, err)
	require.Equal(t, 2, added)
	require.Len(t, recorder.calls, 2)
	require.Equal(t, seccomp.ScmpSyscall(gounix.SYS_SOCKET), recorder.calls[0].syscall)
	require.Equal(t, seccomp.ScmpSyscall(gounix.SYS_SOCKETPAIR), recorder.calls[1].syscall)
	for _, call := range recorder.calls {
		require.Contains(t, call.conditions, seccomp.ScmpCondition{
			Argument: 2,
			Op:       seccomp.CompareEqual,
			Operand1: uint64(gounix.NETLINK_XFRM),
		})
	}
}

func TestInstallSocketRuleConditional_ReportsPartialFailure(t *testing.T) {
	rule := seccompkg.SocketRule{Family: 62, Action: seccompkg.OnBlockLog}
	recorder := &recordingConditionalAdder{failOnCall: 2}

	added, err := installSocketRuleConditional(recorder, rule, seccomp.ActNotify)

	require.Error(t, err)
	require.Equal(t, 1, added)
	require.Len(t, recorder.calls, 2)
}

func TestInstallSocketRulesConditional_RejectsPartialInstall(t *testing.T) {
	rule := seccompkg.SocketRule{Name: "partial", Family: 62, Action: seccompkg.OnBlockLog}
	recorder := &recordingConditionalAdder{failOnCall: 2}

	retained, added, err := installSocketRulesConditional(recorder, []seccompkg.SocketRule{rule})

	require.Error(t, err)
	require.Contains(t, err.Error(), "partial")
	require.Equal(t, 1, added)
	require.Empty(t, retained)
	require.Len(t, recorder.calls, 2)
}

func TestSeccompSocketRuleBlock_Notify_LogDispatched(t *testing.T) {
	if os.Getenv(socketRuleHelperEnv) == socketRuleHelperNotifyLog {
		runSocketRuleHelperNotifyLog(t)
		return
	}

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^TestSeccompSocketRuleBlock_Notify_LogDispatched$", "-test.v")
	cmd.Env = append(os.Environ(), socketRuleHelperEnv+"="+socketRuleHelperNotifyLog)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

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
		t.Errorf("expected matching socket tuple to return EAFNOSUPPORT; helper output:\n%s", combined)
	}
	if !strings.Contains(combined, "audit_event=seccomp_socket_rule_blocked") {
		t.Errorf("expected seccomp_socket_rule_blocked audit event; helper output:\n%s", combined)
	}
	if strings.Contains(combined, "audit_event=seccomp_socket_family_blocked") {
		t.Errorf("socket family event emitted — family dispatch shadowed socket tuple rule;\nhelper output:\n%s", combined)
	}
	if strings.Contains(combined, "audit_event=seccomp_blocked") {
		t.Errorf("generic blocklist event emitted — generic dispatch shadowed socket tuple rule;\nhelper output:\n%s", combined)
	}
}

func TestDirtyFragNetlinkXFRM_ProfileLogAndKillSeccompSocketRule(t *testing.T) {
	if os.Getenv(socketRuleHelperEnv) == socketRuleHelperDirtyFragNetlinkXFRM {
		runDirtyFragSocketRuleHelper(t, socketRuleHelperDirtyFragNetlinkXFRM)
		return
	}

	combined := runSocketRuleHelperSubprocess(t, socketRuleHelperDirtyFragNetlinkXFRM)
	requireResultEAFNOSUPPORT(t, combined, "socket_result")
	require.Contains(t, combined, "audit_event=seccomp_socket_rule_blocked")
	require.Contains(t, combined, "audit_rule=dirtyfrag-conservative-xfrm")
	require.Contains(t, combined, "audit_action=log_and_kill")
	require.Contains(t, combined, "audit_protocol=NETLINK_XFRM")
	require.NotContains(t, combined, "audit_event=seccomp_socket_family_blocked")
	require.NotContains(t, combined, "audit_event=seccomp_blocked")
}

func TestDirtyFragNetlinkRoute_DoesNotDispatchSocketRule(t *testing.T) {
	if os.Getenv(socketRuleHelperEnv) == socketRuleHelperDirtyFragNetlinkRoute {
		runDirtyFragSocketRuleHelper(t, socketRuleHelperDirtyFragNetlinkRoute)
		return
	}

	combined := runSocketRuleHelperSubprocess(t, socketRuleHelperDirtyFragNetlinkRoute)
	require.Contains(t, combined, "socket_result=")
	require.NotContains(t, combined, "audit_event=seccomp_socket_rule_blocked")
	require.NotContains(t, combined, "audit_rule=dirtyfrag-conservative-xfrm")
}

func TestDirtyFragRXRPC_ProfileFamilyOnlyRuleDispatchesAsSocketRule(t *testing.T) {
	if os.Getenv(socketRuleHelperEnv) == socketRuleHelperDirtyFragRXRPC {
		runDirtyFragSocketRuleHelper(t, socketRuleHelperDirtyFragRXRPC)
		return
	}

	combined := runSocketRuleHelperSubprocess(t, socketRuleHelperDirtyFragRXRPC)
	requireResultEAFNOSUPPORT(t, combined, "socket_result")
	require.Contains(t, combined, "audit_event=seccomp_socket_rule_blocked")
	require.Contains(t, combined, "audit_rule=dirtyfrag-conservative-rxrpc")
	require.Contains(t, combined, "audit_action=log_and_kill")
	require.Contains(t, combined, "audit_family=AF_RXRPC")
	require.NotContains(t, combined, "audit_event=seccomp_socket_family_blocked")
	require.NotContains(t, combined, "audit_event=seccomp_blocked")
}

func TestDirtyFragSocketpairNetlinkXFRM_ProfileProtocolRule(t *testing.T) {
	if os.Getenv(socketRuleHelperEnv) == socketRuleHelperDirtyFragSocketpairXFRM {
		runDirtyFragSocketRuleHelper(t, socketRuleHelperDirtyFragSocketpairXFRM)
		return
	}

	combined := runSocketRuleHelperSubprocess(t, socketRuleHelperDirtyFragSocketpairXFRM)
	requireResultEAFNOSUPPORT(t, combined, "socketpair_result")
	require.Contains(t, combined, "audit_event=seccomp_socket_rule_blocked")
	require.Contains(t, combined, "audit_rule=dirtyfrag-conservative-xfrm")
	require.Contains(t, combined, "audit_protocol=NETLINK_XFRM")
	require.Contains(t, combined, "audit_syscall=socketpair")
	require.NotContains(t, combined, "audit_event=seccomp_socket_family_blocked")
	require.NotContains(t, combined, "audit_event=seccomp_blocked")
}

func runSocketRuleHelperSubprocess(t *testing.T, mode string) string {
	t.Helper()

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), socketRuleHelperEnv+"="+mode)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("helper subprocess timed out\noutput:\n%s", combined)
	}
	if strings.Contains(combined, "SKIP:") {
		t.Skipf("child skipped: %s", combined)
	}
	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "lacks user notify") ||
			strings.Contains(lower, "notification ioctl blocked") ||
			strings.Contains(lower, "skip") {
			t.Skipf("host cannot run seccomp notify helper; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("helper subprocess failed: %v\noutput:\n%s", runErr, combined)
	}

	return combined
}

func runDirtyFragSocketRuleHelper(t *testing.T, mode string) {
	t.Helper()

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	rules := dirtyFragProfileSocketRules(t)
	cfg := FilterConfig{
		UnixSocketEnabled: false,
		BlockedSyscalls:   []int{int(gounix.SYS_SOCKET), int(gounix.SYS_SOCKETPAIR)},
		OnBlockAction:     seccompkg.OnBlockLog,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_NETLINK, Action: seccompkg.OnBlockLog, Name: "AF_NETLINK"},
			{Family: gounix.AF_RXRPC, Action: seccompkg.OnBlockLog, Name: "AF_RXRPC"},
		},
		SocketRules: rules,
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "permission") || strings.Contains(lower, "operation not permitted") {
			t.Skipf("cannot install seccomp filter (privilege): %v", err)
		}
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}

	if got := filt.SocketRules(); len(got) != 2 {
		_ = filt.Close()
		t.Fatalf("dirtyfrag profile socket rules not retained for notify; got %d", len(got))
	}

	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return openDevNullFD(t), nil },
		func(pidfd int, sig gounix.Signal) error { return nil },
	)
	defer restore()

	emitter := &captureEventsEmitter{}
	bl := &BlockListConfig{
		ActionByNr:  filt.BlockListMap(),
		FamilyByKey: filt.BlockedFamilyMap(),
		SocketRules: filt.SocketRules(),
	}
	stopNotify := startSocketRuleNotifyHelper(t, filt, bl, emitter)
	defer stopNotify()

	switch mode {
	case socketRuleHelperDirtyFragNetlinkXFRM:
		fd, _, errno := gounix.RawSyscall(
			gounix.SYS_SOCKET,
			uintptr(gounix.AF_NETLINK),
			uintptr(gounix.SOCK_RAW|gounix.SOCK_CLOEXEC),
			uintptr(gounix.NETLINK_XFRM),
		)
		printRawSyscallResult("socket_result", fd, errno)
	case socketRuleHelperDirtyFragNetlinkRoute:
		fd, _, errno := gounix.RawSyscall(
			gounix.SYS_SOCKET,
			uintptr(gounix.AF_NETLINK),
			uintptr(gounix.SOCK_RAW|gounix.SOCK_CLOEXEC),
			uintptr(gounix.NETLINK_ROUTE),
		)
		printRawSyscallResult("socket_result", fd, errno)
	case socketRuleHelperDirtyFragRXRPC:
		fd, _, errno := gounix.RawSyscall(
			gounix.SYS_SOCKET,
			uintptr(gounix.AF_RXRPC),
			uintptr(gounix.SOCK_DGRAM|gounix.SOCK_CLOEXEC),
			0,
		)
		printRawSyscallResult("socket_result", fd, errno)
	case socketRuleHelperDirtyFragSocketpairXFRM:
		// Linux does not create AF_NETLINK socketpairs, but seccomp evaluates
		// the syscall arguments before the kernel rejects the family. This keeps
		// the end-to-end assertion about protocol arg2 without depending on a
		// successful host socketpair implementation.
		var pair [2]int
		fd, _, errno := gounix.RawSyscall6(
			gounix.SYS_SOCKETPAIR,
			uintptr(gounix.AF_NETLINK),
			uintptr(gounix.SOCK_RAW|gounix.SOCK_CLOEXEC),
			uintptr(gounix.NETLINK_XFRM),
			uintptr(unsafe.Pointer(&pair[0])),
			0,
			0,
		)
		if fd != ^uintptr(0) {
			_ = gounix.Close(pair[0])
			_ = gounix.Close(pair[1])
		}
		printRawSyscallResult("socketpair_result", fd, errno)
	default:
		t.Fatalf("unknown dirtyfrag helper mode %q", mode)
	}

	stopNotify()
	printCapturedAuditEvents(emitter.Events())
}

func dirtyFragProfileSocketRules(t *testing.T) []seccompkg.SocketRule {
	t.Helper()

	rules, err := config.ResolveSocketRules(config.SandboxSeccompConfig{
		HardeningProfiles: []string{"dirtyfrag-conservative"},
	})
	require.NoError(t, err)
	require.Len(t, rules, 2)
	return rules
}

func startSocketRuleNotifyHelper(t *testing.T, filt *Filter, bl *BlockListConfig, emitter Emitter) func() {
	t.Helper()

	notifFD := filt.NotifFD()
	if notifFD < 0 {
		t.Fatalf("expected valid notify fd; got %d", notifFD)
	}
	if err := ProbeNotifReceive(notifFD); err != nil {
		_ = filt.Close()
		if errors.Is(err, ErrNotifyBlocked) {
			t.Skipf("seccomp notification ioctl blocked: %v", err)
		}
		t.Fatalf("probe seccomp notification fd: %v", err)
	}

	notifyFile := os.NewFile(uintptr(notifFD), "seccomp-notify")
	if notifyFile == nil {
		_ = filt.Close()
		t.Fatalf("os.NewFile returned nil for notify fd %d", notifFD)
	}
	filt.fd = -1

	ctx, cancel := context.WithCancel(context.Background())
	if capture, ok := emitter.(*captureEventsEmitter); ok {
		var cancelOnce sync.Once
		capture.SetOnEvent(func() {
			cancelOnce.Do(cancel)
		})
	}
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		ServeNotifyWithExecve(ctx, notifyFile, "test-dirtyfrag-socket-rules", nil, emitter, nil, nil, bl)
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			_ = notifyFile.Close()
			select {
			case <-handlerDone:
			case <-time.After(2 * time.Second):
				t.Fatalf("seccomp notify handler did not exit in time")
			}
		})
	}
}

func printRawSyscallResult(label string, fd uintptr, errno gounix.Errno) {
	if fd != ^uintptr(0) {
		_ = gounix.Close(int(fd))
		fmt.Printf("%s=OK\n", label)
		return
	}
	fmt.Printf("%s=%v (errno=%d)\n", label, errno, int(errno))
}

func requireResultEAFNOSUPPORT(t *testing.T, combined, label string) {
	t.Helper()

	if !strings.Contains(combined, label+"=EAFNOSUPPORT") &&
		!strings.Contains(combined, label+"=address family not supported") &&
		!strings.Contains(combined, "errno=97") {
		t.Fatalf("expected %s to return EAFNOSUPPORT; helper output:\n%s", label, combined)
	}
}

type captureEventsEmitter struct {
	mu      sync.Mutex
	events  []types.Event
	onEvent func()
}

func (e *captureEventsEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	e.add(ev)
	return nil
}

func (e *captureEventsEmitter) Publish(ev types.Event) {
	e.add(ev)
}

func (e *captureEventsEmitter) add(ev types.Event) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	onEvent := e.onEvent
	e.mu.Unlock()

	if onEvent != nil {
		onEvent()
	}
}

func (e *captureEventsEmitter) Events() []types.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]types.Event, len(e.events))
	copy(out, e.events)
	return out
}

func (e *captureEventsEmitter) SetOnEvent(fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onEvent = fn
}

func printCapturedAuditEvents(events []types.Event) {
	seen := map[string]struct{}{}
	for _, ev := range events {
		key := fmt.Sprintf(
			"%s|%v|%v|%v|%v|%v|%v",
			ev.Type,
			ev.Fields["rule_name"],
			ev.Fields["action"],
			ev.Fields["family_name"],
			ev.Fields["protocol_name"],
			ev.Fields["syscall"],
			ev.Fields["outcome"],
		)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		fmt.Printf("audit_event=%s\n", ev.Type)
		if v, ok := ev.Fields["rule_name"]; ok {
			fmt.Printf("audit_rule=%v\n", v)
		}
		if v, ok := ev.Fields["action"]; ok {
			fmt.Printf("audit_action=%v\n", v)
		}
		if v, ok := ev.Fields["family_name"]; ok {
			fmt.Printf("audit_family=%v\n", v)
		}
		if v, ok := ev.Fields["protocol_name"]; ok {
			fmt.Printf("audit_protocol=%v\n", v)
		}
		if v, ok := ev.Fields["syscall"]; ok {
			fmt.Printf("audit_syscall=%v\n", v)
		}
		if v, ok := ev.Fields["outcome"]; ok {
			fmt.Printf("audit_outcome=%v\n", v)
		}
	}
}

func runSocketRuleHelperNotifyLog(t *testing.T) {
	t.Helper()

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	typ := int(gounix.SOCK_RAW)
	protocol := int(gounix.NETLINK_XFRM)
	rule := seccompkg.SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       gounix.AF_NETLINK,
		FamilyName:   "AF_NETLINK",
		Type:         &typ,
		TypeName:     "SOCK_RAW",
		Protocol:     &protocol,
		ProtocolName: "NETLINK_XFRM",
		Action:       seccompkg.OnBlockLog,
	}
	cfg := FilterConfig{
		UnixSocketEnabled: false,
		BlockedSyscalls:   []int{int(gounix.SYS_SOCKET)},
		OnBlockAction:     seccompkg.OnBlockLog,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: gounix.AF_NETLINK, Action: seccompkg.OnBlockLog, Name: "AF_NETLINK"},
		},
		SocketRules: []seccompkg.SocketRule{rule},
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

	bl := &BlockListConfig{
		ActionByNr:  filt.BlockListMap(),
		FamilyByKey: filt.BlockedFamilyMap(),
		SocketRules: filt.SocketRules(),
	}
	if len(bl.SocketRules) == 0 {
		t.Fatalf("SocketRules is empty; log socket rule should populate it")
	}

	var (
		mu     sync.Mutex
		events []string
	)
	emitter := &captureEmitter{fn: func(typ string) {
		mu.Lock()
		events = append(events, typ)
		mu.Unlock()
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifyFile := os.NewFile(uintptr(notifFD), "seccomp-notify")
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		ServeNotifyWithExecve(ctx, notifyFile, "test-socket-rule-notify", nil, emitter, nil, nil, bl)
	}()

	fd, _, errno := gounix.RawSyscall(
		gounix.SYS_SOCKET,
		uintptr(gounix.AF_NETLINK),
		uintptr(gounix.SOCK_RAW|gounix.SOCK_CLOEXEC),
		uintptr(gounix.NETLINK_XFRM),
	)
	if fd != ^uintptr(0) {
		_ = gounix.Close(int(fd))
		fmt.Printf("socket_result=OK (expected EAFNOSUPPORT)\n")
	} else {
		fmt.Printf("socket_result=%v (errno=%d)\n", errno, int(errno))
	}

	cancel()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		fmt.Printf("handler did not exit in time\n")
	}

	mu.Lock()
	defer mu.Unlock()
	for _, ev := range events {
		fmt.Printf("audit_event=%s\n", ev)
	}
}

func TestSeccompSocketRuleBlock_ErrnoTuple(t *testing.T) {
	if os.Getenv(socketRuleHelperEnv) == "errno_tuple" {
		runSocketRuleHelperErrnoTuple(t)
		return
	}

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^TestSeccompSocketRuleBlock_ErrnoTuple$", "-test.v")
	cmd.Env = append(os.Environ(), socketRuleHelperEnv+"=errno_tuple")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

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
		t.Errorf("expected matching socket tuple to return EAFNOSUPPORT; helper output:\n%s", combined)
	}
}

func runSocketRuleHelperErrnoTuple(t *testing.T) {
	t.Helper()

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	typ := int(gounix.SOCK_RAW)
	protocol := int(gounix.NETLINK_XFRM)
	cfg := FilterConfig{
		SocketRules: []seccompkg.SocketRule{
			{
				Name:         "netlink_xfrm",
				Family:       gounix.AF_NETLINK,
				FamilyName:   "AF_NETLINK",
				Type:         &typ,
				TypeName:     "SOCK_RAW",
				Protocol:     &protocol,
				ProtocolName: "NETLINK_XFRM",
				Action:       seccompkg.OnBlockErrno,
			},
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

	fd, _, errno := gounix.RawSyscall(
		gounix.SYS_SOCKET,
		uintptr(gounix.AF_NETLINK),
		uintptr(gounix.SOCK_RAW|gounix.SOCK_CLOEXEC),
		uintptr(gounix.NETLINK_XFRM),
	)
	if fd != ^uintptr(0) {
		_ = gounix.Close(int(fd))
		fmt.Printf("socket_result=OK (expected EAFNOSUPPORT)\n")
		return
	}
	fmt.Printf("socket_result=%v (errno=%d)\n", errno, int(errno))
}

func TestFilterDiagnosticFields_RulesSocketRules(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	require.NoError(t, err)

	fields := filterDiagnosticFields(filt, FilterConfig{}, false, map[string]int{
		"blocked_syscalls": 2,
		"socket_rules":     4,
	})

	got := diagnosticFieldsMap(fields)
	require.Equal(t, 6, got["rules_total"])
	require.Equal(t, 4, got["rules_socket_rules"])
}

type recordingConditionalAdder struct {
	failOnCall int
	calls      []recordedConditionalCall
}

type recordedConditionalCall struct {
	syscall    seccomp.ScmpSyscall
	action     seccomp.ScmpAction
	conditions []seccomp.ScmpCondition
}

func (r *recordingConditionalAdder) AddRuleConditional(call seccomp.ScmpSyscall, action seccomp.ScmpAction, conds []seccomp.ScmpCondition) error {
	copied := append([]seccomp.ScmpCondition(nil), conds...)
	r.calls = append(r.calls, recordedConditionalCall{
		syscall:    call,
		action:     action,
		conditions: copied,
	})
	if r.failOnCall != 0 && len(r.calls) == r.failOnCall {
		return errors.New("synthetic add failure")
	}
	return nil
}

func diagnosticFieldsMap(fields []any) map[string]any {
	out := make(map[string]any, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if ok {
			out[key] = fields[i+1]
		}
	}
	return out
}
