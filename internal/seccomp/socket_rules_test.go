package seccomp

import "testing"

func TestParseFamilyIncludesRxRPC(t *testing.T) {
	nr, name, ok := ParseFamily("AF_RXRPC")
	if !ok {
		t.Fatal("AF_RXRPC should parse")
	}
	if nr != 33 || name != "AF_RXRPC" {
		t.Fatalf("ParseFamily(AF_RXRPC) = (%d, %q), want (33, AF_RXRPC)", nr, name)
	}
}

func TestParseSocketProtocol(t *testing.T) {
	cases := []struct {
		in       string
		wantNr   int
		wantName string
		wantOK   bool
	}{
		{"NETLINK_XFRM", 6, "NETLINK_XFRM", true},
		{"NETLINK_ROUTE", 0, "NETLINK_ROUTE", true},
		{"6", 6, "", true},
		{"NETLINK_NOT_REAL", 0, "", false},
		{"-1", 0, "", false},
		{"9999", 0, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			gotNr, gotName, gotOK := ParseSocketProtocol(tc.in)
			if gotNr != tc.wantNr || gotName != tc.wantName || gotOK != tc.wantOK {
				t.Fatalf("ParseSocketProtocol(%q) = (%d, %q, %v), want (%d, %q, %v)",
					tc.in, gotNr, gotName, gotOK, tc.wantNr, tc.wantName, tc.wantOK)
			}
		})
	}
}

func TestParseSocketType(t *testing.T) {
	cases := []struct {
		in       string
		wantNr   int
		wantName string
		wantOK   bool
	}{
		{"SOCK_STREAM", 1, "SOCK_STREAM", true},
		{"SOCK_DGRAM", 2, "SOCK_DGRAM", true},
		{"SOCK_SEQPACKET", 5, "SOCK_SEQPACKET", true},
		{"3", 3, "", true},
		{"SOCK_NOT_REAL", 0, "", false},
		{"0", 0, "", false},
		{"9999", 0, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			gotNr, gotName, gotOK := ParseSocketType(tc.in)
			if gotNr != tc.wantNr || gotName != tc.wantName || gotOK != tc.wantOK {
				t.Fatalf("ParseSocketType(%q) = (%d, %q, %v), want (%d, %q, %v)",
					tc.in, gotNr, gotName, gotOK, tc.wantNr, tc.wantName, tc.wantOK)
			}
		})
	}
}

func TestSocketRuleMatches(t *testing.T) {
	proto := 6
	rule := SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       16,
		FamilyName:   "AF_NETLINK",
		Protocol:     &proto,
		ProtocolName: "NETLINK_XFRM",
		Action:       OnBlockLogAndKill,
	}
	if !rule.MatchesSocket(16, 0, 6) {
		t.Fatal("expected NETLINK_XFRM socket to match")
	}
	if rule.MatchesSocket(16, 0, 0) {
		t.Fatal("NETLINK_ROUTE must not match NETLINK_XFRM rule")
	}
	if rule.MatchesSocketpair(16, 0) {
		t.Fatal("protocol-constrained rules must not match socketpair")
	}
}

func TestSocketRuleTypeMatchIgnoresFlags(t *testing.T) {
	typ := 1
	rule := SocketRule{Name: "stream", Family: 2, Type: &typ, Action: OnBlockErrno}
	if !rule.MatchesSocket(2, 1|SocketTypeFlagCloexec|SocketTypeFlagNonblock, 0) {
		t.Fatal("type matching should ignore SOCK_CLOEXEC and SOCK_NONBLOCK flags")
	}
}
