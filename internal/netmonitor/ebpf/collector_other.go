//go:build !linux

package ebpf

import "errors"

// ConnectEvent stub for non-Linux platforms, keeping the same fields for build compatibility.
type ConnectEvent struct {
	TsNs     uint64
	Cookie   uint64
	PID      uint32
	TGID     uint32
	Sport    uint16
	Dport    uint16
	Family   uint8
	Protocol uint8
	_        [6]byte
	DstIPv4  uint32
	DstIPv6  [16]byte
	Blocked  uint8
	_pad     [7]byte
}

// Collector stub for non-Linux platforms.
type Collector struct{}

func StartCollector(_ any, _ int) (*Collector, error) {
	return nil, errors.New("ebpf collector not supported")
}
func (c *Collector) Events() <-chan ConnectEvent { return nil }
func (c *Collector) Close() error                { return nil }
func (c *Collector) SetOnDrop(_ func())          {}
