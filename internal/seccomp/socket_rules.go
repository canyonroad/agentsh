package seccomp

import "strconv"

const (
	SocketTypeMask         = 0xf
	SocketTypeFlagNonblock = 0x800
	SocketTypeFlagCloexec  = 0x80000
)

type SocketRule struct {
	Name         string        `json:"name,omitempty"`
	Family       int           `json:"family"`
	FamilyName   string        `json:"family_name,omitempty"`
	Type         *int          `json:"type,omitempty"`
	TypeName     string        `json:"type_name,omitempty"`
	Protocol     *int          `json:"protocol,omitempty"`
	ProtocolName string        `json:"protocol_name,omitempty"`
	Action       OnBlockAction `json:"action"`
}

var protocolNameTable = map[string]int{
	"NETLINK_ROUTE":          0,
	"NETLINK_USERSOCK":       2,
	"NETLINK_FIREWALL":       3,
	"NETLINK_SOCK_DIAG":      4,
	"NETLINK_NFLOG":          5,
	"NETLINK_XFRM":           6,
	"NETLINK_SELINUX":        7,
	"NETLINK_ISCSI":          8,
	"NETLINK_AUDIT":          9,
	"NETLINK_FIB_LOOKUP":     10,
	"NETLINK_CONNECTOR":      11,
	"NETLINK_NETFILTER":      12,
	"NETLINK_KOBJECT_UEVENT": 15,
	"NETLINK_GENERIC":        16,
}

var socketTypeNameTable = map[string]int{
	"SOCK_STREAM":    1,
	"SOCK_DGRAM":     2,
	"SOCK_RAW":       3,
	"SOCK_RDM":       4,
	"SOCK_SEQPACKET": 5,
}

func ParseSocketProtocol(value string) (nr int, name string, ok bool) {
	if value == "" {
		return 0, "", false
	}
	if n, found := protocolNameTable[value]; found {
		return n, value, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 || parsed >= 64 {
		return 0, "", false
	}
	return parsed, "", true
}

func ParseSocketType(value string) (nr int, name string, ok bool) {
	if value == "" {
		return 0, "", false
	}
	if n, found := socketTypeNameTable[value]; found {
		return n, value, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 || parsed > SocketTypeMask {
		return 0, "", false
	}
	return parsed, "", true
}

func (r SocketRule) MatchesSocket(family, typ, protocol uint64) bool {
	if uint64(r.Family) != family {
		return false
	}
	if r.Type != nil && uint64(*r.Type) != (typ&SocketTypeMask) {
		return false
	}
	if r.Protocol != nil && uint64(*r.Protocol) != protocol {
		return false
	}
	return true
}

func (r SocketRule) MatchesSocketpair(family, typ uint64) bool {
	if r.Protocol != nil {
		return false
	}
	if uint64(r.Family) != family {
		return false
	}
	if r.Type != nil && uint64(*r.Type) != (typ&SocketTypeMask) {
		return false
	}
	return true
}
