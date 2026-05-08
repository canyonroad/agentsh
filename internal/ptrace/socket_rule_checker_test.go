//go:build linux

package ptrace

import (
	"context"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

func intPtr(v int) *int {
	return &v
}

func TestSocketRuleChecker_Check_MatchMissTypeMaskAndNilReceiver(t *testing.T) {
	rule := seccomp.SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       unix.AF_NETLINK,
		FamilyName:   "AF_NETLINK",
		Type:         intPtr(unix.SOCK_RAW),
		TypeName:     "SOCK_RAW",
		Protocol:     intPtr(unix.NETLINK_XFRM),
		ProtocolName: "NETLINK_XFRM",
		Action:       seccomp.OnBlockLogAndKill,
	}
	c := NewSocketRuleChecker([]seccomp.SocketRule{rule})

	got, ok := c.Check(
		uint64(unix.SYS_SOCKET),
		uint64(unix.AF_NETLINK),
		uint64(unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK),
		uint64(unix.NETLINK_XFRM),
	)
	if !ok || got.Name != "dirtyfrag-xfrm" {
		t.Fatalf("expected NETLINK_XFRM socket match with masked type; got rule=%+v ok=%v", got, ok)
	}

	if _, ok := c.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_ROUTE)); ok {
		t.Fatal("NETLINK_ROUTE must not match a NETLINK_XFRM socket rule")
	}
	if _, ok := c.Check(uint64(unix.SYS_BIND), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_XFRM)); ok {
		t.Fatal("non-socket syscalls must not match socket tuple rules")
	}
	if _, ok := NewSocketRuleChecker(nil).Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_XFRM)); ok {
		t.Fatal("empty checker should never match")
	}
	var nilChecker *SocketRuleChecker
	if _, ok := nilChecker.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_XFRM)); ok {
		t.Fatal("nil checker should never match")
	}
}

func TestSocketRuleChecker_Check_SocketpairUsesProtocolArg2(t *testing.T) {
	rule := seccomp.SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       unix.AF_NETLINK,
		FamilyName:   "AF_NETLINK",
		Type:         intPtr(unix.SOCK_DGRAM),
		TypeName:     "SOCK_DGRAM",
		Protocol:     intPtr(unix.NETLINK_XFRM),
		ProtocolName: "NETLINK_XFRM",
		Action:       seccomp.OnBlockLogAndKill,
	}
	c := NewSocketRuleChecker([]seccomp.SocketRule{rule})

	if _, ok := c.Check(uint64(unix.SYS_SOCKETPAIR), uint64(unix.AF_NETLINK), uint64(unix.SOCK_DGRAM), uint64(unix.NETLINK_XFRM)); !ok {
		t.Fatal("socketpair(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM) should match")
	}
	if _, ok := c.Check(uint64(unix.SYS_SOCKETPAIR), uint64(unix.AF_NETLINK), uint64(unix.SOCK_DGRAM), uint64(unix.NETLINK_ROUTE)); ok {
		t.Fatal("socketpair protocol arg2 must be honored")
	}
}

func TestSocketRuleChecker_ConstructionCopiesRulePointers(t *testing.T) {
	typ := unix.SOCK_RAW
	proto := unix.NETLINK_XFRM
	rules := []seccomp.SocketRule{{
		Name:         "dirtyfrag-xfrm",
		Family:       unix.AF_NETLINK,
		FamilyName:   "AF_NETLINK",
		Type:         &typ,
		TypeName:     "SOCK_RAW",
		Protocol:     &proto,
		ProtocolName: "NETLINK_XFRM",
		Action:       seccomp.OnBlockLogAndKill,
	}}

	c := NewSocketRuleChecker(rules)
	typ = unix.SOCK_DGRAM
	proto = unix.NETLINK_ROUTE

	if _, ok := c.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_XFRM)); !ok {
		t.Fatal("checker should retain original Type/Protocol values after caller mutates input pointers")
	}
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_DGRAM), uint64(unix.NETLINK_ROUTE)); ok {
		t.Fatal("checker should not observe caller mutations to input Type/Protocol pointers")
	}
}

func TestSocketRuleChecker_CheckReturnsRuleCopy(t *testing.T) {
	rule := seccomp.SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       unix.AF_NETLINK,
		FamilyName:   "AF_NETLINK",
		Type:         intPtr(unix.SOCK_RAW),
		TypeName:     "SOCK_RAW",
		Protocol:     intPtr(unix.NETLINK_XFRM),
		ProtocolName: "NETLINK_XFRM",
		Action:       seccomp.OnBlockLogAndKill,
	}
	c := NewSocketRuleChecker([]seccomp.SocketRule{rule})

	got, ok := c.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_XFRM))
	if !ok {
		t.Fatal("expected initial socket rule match")
	}
	*got.Type = unix.SOCK_DGRAM
	*got.Protocol = unix.NETLINK_ROUTE

	if _, ok := c.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_XFRM)); !ok {
		t.Fatal("mutating returned rule pointers should not mutate checker-owned rule")
	}
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_DGRAM), uint64(unix.NETLINK_ROUTE)); ok {
		t.Fatal("checker should not observe mutations to a rule returned by Check")
	}
}

func TestSocketRuleChecker_ApplyLogEmitsPtraceEventAndDenies(t *testing.T) {
	rule := seccomp.SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       unix.AF_NETLINK,
		FamilyName:   "AF_NETLINK",
		Type:         intPtr(unix.SOCK_RAW),
		TypeName:     "SOCK_RAW",
		Protocol:     intPtr(unix.NETLINK_XFRM),
		ProtocolName: "NETLINK_XFRM",
		Action:       seccomp.OnBlockLog,
	}
	sink := &applyTestEmitter{}
	c := NewSocketRuleCheckerWithEmitter([]seccomp.SocketRule{rule}, sink)
	var denied bool
	c.denySyscallFn = func(tid int, errno int) error {
		if tid != 100 {
			t.Fatalf("deny tid=%d, want 100", tid)
		}
		if errno != int(unix.EAFNOSUPPORT) {
			t.Fatalf("deny errno=%d, want EAFNOSUPPORT", errno)
		}
		denied = true
		return nil
	}

	err := c.Apply(100, 200, nil, rule.Action, unix.SYS_SOCKETPAIR, rule, "sess-socket-rule")
	if err != ptraceAlreadyResumed {
		t.Fatalf("Apply return=%v, want ptraceAlreadyResumed", err)
	}
	if !denied {
		t.Fatal("expected log action to deny the syscall")
	}

	evts := sink.Events()
	if len(evts) == 0 {
		t.Fatal("expected audit event")
	}
	ev := evts[0]
	if ev.Type != "seccomp_socket_rule_blocked" {
		t.Fatalf("event type=%q, want seccomp_socket_rule_blocked", ev.Type)
	}
	if ev.SessionID != "sess-socket-rule" || ev.Source != "ptrace" || ev.PID != 100 {
		t.Fatalf("unexpected event identity: session=%q source=%q pid=%d", ev.SessionID, ev.Source, ev.PID)
	}
	assertField(t, ev.Fields, "rule_name", "dirtyfrag-xfrm")
	assertField(t, ev.Fields, "family_name", "AF_NETLINK")
	assertField(t, ev.Fields, "family_number", unix.AF_NETLINK)
	assertField(t, ev.Fields, "type_name", "SOCK_RAW")
	assertField(t, ev.Fields, "type_number", unix.SOCK_RAW)
	assertField(t, ev.Fields, "protocol_name", "NETLINK_XFRM")
	assertField(t, ev.Fields, "protocol_number", unix.NETLINK_XFRM)
	assertField(t, ev.Fields, "syscall", "socketpair")
	assertField(t, ev.Fields, "syscall_nr", uint32(unix.SYS_SOCKETPAIR))
	assertField(t, ev.Fields, "action", string(seccomp.OnBlockLog))
	assertField(t, ev.Fields, "outcome", "denied")
	assertField(t, ev.Fields, "engine", "ptrace")
	assertField(t, ev.Fields, "arch", runtime.GOARCH)
}

func TestSocketRuleChecker_ApplyLogAndKillEmitsKilledOutcome(t *testing.T) {
	rule := seccomp.SocketRule{
		Name:       "dirtyfrag-rxrpc",
		Family:     unix.AF_RXRPC,
		FamilyName: "AF_RXRPC",
		Action:     seccomp.OnBlockLogAndKill,
	}
	sink := &applyTestEmitter{}
	c := NewSocketRuleCheckerWithEmitter([]seccomp.SocketRule{rule}, sink)
	c.tgkillFn = func(tgid, tid int, sig unix.Signal) error {
		if tgid != 200 || tid != 100 || sig != unix.SIGKILL {
			t.Fatalf("tgkill(%d,%d,%v), want (200,100,SIGKILL)", tgid, tid, sig)
		}
		return nil
	}
	c.denySyscallFn = func(tid int, errno int) error {
		t.Fatal("denySyscall must not be called when tgkill succeeds")
		return nil
	}

	err := c.Apply(100, 200, nil, rule.Action, unix.SYS_SOCKET, rule, "sess-kill")
	if err != PtraceKillRequested {
		t.Fatalf("Apply return=%v, want PtraceKillRequested", err)
	}

	evts := sink.Events()
	if len(evts) == 0 {
		t.Fatal("expected audit event")
	}
	assertField(t, evts[0].Fields, "outcome", "killed")
	assertField(t, evts[0].Fields, "engine", "ptrace")
}

func TestSocketRuleChecker_ApplyErrnoDeniesWithoutEvent(t *testing.T) {
	rule := seccomp.SocketRule{
		Name:       "dirtyfrag-rxrpc",
		Family:     unix.AF_RXRPC,
		FamilyName: "AF_RXRPC",
		Action:     seccomp.OnBlockErrno,
	}
	sink := &applyTestEmitter{}
	c := NewSocketRuleCheckerWithEmitter([]seccomp.SocketRule{rule}, sink)
	var denied bool
	c.denySyscallFn = func(tid int, errno int) error {
		denied = true
		return nil
	}

	err := c.Apply(100, 200, nil, rule.Action, unix.SYS_SOCKET, rule, "sess-errno")
	if err != ptraceAlreadyResumed {
		t.Fatalf("Apply return=%v, want ptraceAlreadyResumed", err)
	}
	if !denied {
		t.Fatal("expected errno action to deny the syscall")
	}
	if got := sink.Events(); len(got) != 0 {
		t.Fatalf("errno action should not emit events, got %d", len(got))
	}
}

func TestDispatchSyscall_SocketRuleWinsOverFamilyAndNetwork(t *testing.T) {
	rule := seccomp.SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       unix.AF_NETLINK,
		FamilyName:   "AF_NETLINK",
		Protocol:     intPtr(unix.NETLINK_XFRM),
		ProtocolName: "NETLINK_XFRM",
		Action:       seccomp.OnBlockLog,
	}
	socketChecker := NewSocketRuleChecker([]seccomp.SocketRule{rule})
	var socketDenied int
	socketChecker.denySyscallFn = func(tid int, errno int) error {
		socketDenied++
		return nil
	}

	familyChecker := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: unix.AF_NETLINK, Name: "AF_NETLINK", Action: seccomp.OnBlockLog},
	})
	familyChecker.denySyscallFn = func(tid int, errno int) error {
		t.Fatal("family checker must not run after a socket tuple match")
		return nil
	}

	networkHandler := &countingNetworkHandler{}
	tr := NewTracer(TracerConfig{
		TraceNetwork:      true,
		NetworkHandler:    networkHandler,
		SocketRuleChecker: socketChecker,
		FamilyChecker:     familyChecker,
	})
	tr.tracees[123] = &TraceeState{TID: 123, TGID: 456, SessionID: "sess-dispatch"}

	tr.dispatchSyscall(context.Background(), 123, unix.SYS_SOCKET, &SyscallContext{
		Info: SyscallEntryInfo{
			Nr: unix.SYS_SOCKET,
			Args: [6]uint64{
				uint64(unix.AF_NETLINK),
				uint64(unix.SOCK_RAW),
				uint64(unix.NETLINK_XFRM),
			},
		},
	})

	if socketDenied != 1 {
		t.Fatalf("socket checker deny calls=%d, want 1", socketDenied)
	}
	if networkHandler.calls != 0 {
		t.Fatalf("network handler calls=%d, want 0", networkHandler.calls)
	}
}

type countingNetworkHandler struct {
	calls int
}

func (h *countingNetworkHandler) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	h.calls++
	return NetworkResult{Allow: true}
}

func assertField(t *testing.T, fields map[string]any, key string, want any) {
	t.Helper()
	if got := fields[key]; got != want {
		t.Fatalf("field %q=%#v, want %#v", key, got, want)
	}
}
