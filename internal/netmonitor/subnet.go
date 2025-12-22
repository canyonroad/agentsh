package netmonitor

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// AllocateSubnet deterministically assigns a /24 within subnetBase (CIDR) based on nsName.
// Returns (subnetCIDR, hostIPCIDR, nsIPCIDR, hostIfName, nsIfName).
func AllocateSubnet(subnetBase string, nsName string) (string, string, string, string, string) {
	_, ipnet, err := net.ParseCIDR(subnetBase)
	if err != nil {
		// Fallback.
		subnetBase = "10.250.0.0/16"
		_, ipnet, _ = net.ParseCIDR(subnetBase)
	}

	base := ipnet.IP.To4()
	if base == nil {
		base = net.IPv4(10, 250, 0, 0)
	}

	h := sha1.Sum([]byte(nsName))
	oct := int(h[0])
	if oct == 0 {
		oct = 1
	}
	if oct > 250 {
		oct = oct % 250
		if oct == 0 {
			oct = 1
		}
	}

	// Construct 10.250.<oct>.0/24 (works for default /16 base).
	subnetIP := net.IPv4(base[0], base[1], byte(oct), 0)
	subnetCIDR := fmt.Sprintf("%s/24", subnetIP.String())
	hostIPCIDR := fmt.Sprintf("%s/24", net.IPv4(base[0], base[1], byte(oct), 1).String())
	nsIPCIDR := fmt.Sprintf("%s/24", net.IPv4(base[0], base[1], byte(oct), 2).String())

	short := fmt.Sprintf("%x", binary.LittleEndian.Uint16(h[:2]))
	hostIf := "veth" + short
	nsIf := "veth" + short + "n"
	hostIf = strings.ReplaceAll(hostIf, "-", "")
	nsIf = strings.ReplaceAll(nsIf, "-", "")
	return subnetCIDR, hostIPCIDR, nsIPCIDR, hostIf, nsIf
}
