//go:build linux && cgo

package seccomp

import "strconv"

// BlockedFamily is one entry on the blocked_socket_families list.
type BlockedFamily struct {
	Family int           // resolved AF_* number
	Action OnBlockAction // errno|kill|log|log_and_kill
	Name   string        // original config name; "" if numeric
}

// nameTable maps human-readable AF_* names to their kernel numbers.
// New families need a code update — kernel adds them rarely.
var nameTable = map[string]int{
	"AF_UNIX":      1,
	"AF_INET":      2,
	"AF_AX25":      3,
	"AF_IPX":       4,
	"AF_APPLETALK": 5,
	"AF_NETROM":    6,
	"AF_X25":       9,
	"AF_INET6":     10,
	"AF_ROSE":      11,
	"AF_DECnet":    12,
	"AF_NETLINK":   16,
	"AF_PACKET":    17,
	"AF_RDS":       21,
	"AF_CAN":       29,
	"AF_TIPC":      30,
	"AF_BLUETOOTH": 31,
	"AF_ALG":       38,
	"AF_VSOCK":     40,
	"AF_KCM":       41,
}

// ParseFamily resolves a config value (name string or numeric string) to
// its AF_* int. Returns ok=false if the value is neither a known name
// nor a parseable integer in [0, 64).
//
// On numeric input, name is returned as "" so callers can preserve the
// fact that the operator chose a number.
func ParseFamily(value string) (nr int, name string, ok bool) {
	if value == "" {
		return 0, "", false
	}
	if n, found := nameTable[value]; found {
		return n, value, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, "", false
	}
	if parsed < 0 || parsed >= 64 {
		// AF_MAX is currently 47 in mainline; 64 leaves headroom but
		// rejects clearly-bogus values like 1000.
		return 0, "", false
	}
	return parsed, "", true
}

// DefaultBlockedFamilies returns the recommended-default list applied
// when blocked_socket_families is unset in config. Each entry uses
// OnBlockErrno (returns EAFNOSUPPORT to userspace).
//
// Rationale per docs/superpowers/specs/2026-04-29-socket-family-block-design.md.
func DefaultBlockedFamilies() []BlockedFamily {
	names := []string{
		"AF_ALG", "AF_VSOCK", "AF_RDS", "AF_TIPC", "AF_KCM",
		"AF_X25", "AF_AX25", "AF_NETROM", "AF_ROSE", "AF_DECnet",
		"AF_APPLETALK", "AF_IPX",
	}
	out := make([]BlockedFamily, 0, len(names))
	for _, n := range names {
		out = append(out, BlockedFamily{
			Family: nameTable[n],
			Action: OnBlockErrno,
			Name:   n,
		})
	}
	return out
}
