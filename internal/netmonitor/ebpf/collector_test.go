//go:build linux

package ebpf

import "testing"

func TestCopyToEventBounds(t *testing.T) {
	var ev ConnectEvent
	data := make([]byte, 48)
	copyToEvent(&ev, data)
}
