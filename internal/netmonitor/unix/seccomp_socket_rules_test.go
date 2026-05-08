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

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

const socketRuleHelperEnv = "AGENTSH_TEST_SOCKET_RULE_HELPER"
const socketRuleHelperNotifyLog = "notify_log"

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
