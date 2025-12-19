package ebpf

import "sync"

// resetOverrides is for tests only; it clears override state so tests can set different values.
func resetOverrides() {
	mapAllowOverride = 0
	mapDenyOverride = 0
	mapLPMOverride = 0
	mapLPMDenyOverride = 0
	mapDefaultOverride = 0
	mapOverrideOnce = sync.Once{}
}
