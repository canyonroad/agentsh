//go:build !linux

package netmonitor

import (
	"context"
	"fmt"
)

type NetNS struct{}

func SetupNetNS(ctx context.Context, nsName string, subnetCIDR string, hostIf string, nsIf string, hostIPCIDR string, nsIPCIDR string, proxyTCPPort int, dnsUDPPort int) (*NetNS, error) {
	return nil, fmt.Errorf("transparent netns not supported on this platform")
}

func (n *NetNS) Close(ctx context.Context) error { return nil }

