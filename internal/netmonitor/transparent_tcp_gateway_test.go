//go:build linux

package netmonitor

import "testing"

func TestSetTorGateway_PortPredicate(t *testing.T) {
	tcp := &TransparentTCP{}
	tcp.SetTorGateway(fakeGatewayPolicy{allow: "ok.onion"}, "127.0.0.1:9050", []int{9050, 9150})

	if _, ok := tcp.torGatewayFor(9050); !ok {
		t.Error("9050 should route to gateway")
	}
	if _, ok := tcp.torGatewayFor(9150); !ok {
		t.Error("9150 should route to gateway")
	}
	if _, ok := tcp.torGatewayFor(443); ok {
		t.Error("443 must NOT route to gateway")
	}

	// Clearing disables routing.
	tcp.SetTorGateway(nil, "", nil)
	if _, ok := tcp.torGatewayFor(9050); ok {
		t.Error("cleared gateway must not route")
	}
}
