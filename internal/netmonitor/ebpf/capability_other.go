//go:build !linux

package ebpf

// SupportStatus describes whether eBPF tracing is usable on this host.
type SupportStatus struct {
	Supported bool
	Reason    string
}

// CheckSupport reports eBPF support on non-Linux platforms (always false).
func CheckSupport() SupportStatus {
	return SupportStatus{Supported: false, Reason: "ebpf network tracing is only available on linux"}
}
