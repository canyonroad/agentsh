//go:build !linux

package ebpf

import "errors"

// Collector stub for non-Linux platforms.
type Collector struct{}

func StartCollector(_ any, _ int) (*Collector, error) {
	return nil, errors.New("ebpf collector not supported")
}
func (c *Collector) Events() <-chan ConnectEvent { return nil }
func (c *Collector) Close() error                { return nil }
