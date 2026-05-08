//go:build linux && cgo

package unix

import (
	"errors"
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

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
