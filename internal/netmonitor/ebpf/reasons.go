package ebpf

// Reason substrings returned by CheckSupport. These are matched by the
// tip system in internal/capabilities to produce reason-specific
// remediation advice. Changing these values requires updating the
// corresponding entries in tipsByBackend.
const (
	ReasonBTFNotPresent       = "btf not present"
	ReasonCgroupV2NotAvail    = "cgroup v2 not available"
	ReasonKernelVersionUnknown = "kernel version unknown"
	ReasonKernelTooOld        = "kernel"
	ReasonMissingCap          = "missing CAP_BPF or CAP_SYS_ADMIN"
)
