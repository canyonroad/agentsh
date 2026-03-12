//go:build linux

package ptrace

import (
	"testing"
)

func TestNopMetrics(t *testing.T) {
	// nopMetrics must not panic on any call.
	var m nopMetrics
	m.SetTraceeCount(5)
	m.IncAttachFailure("eperm")
	m.IncTimeout()
}
