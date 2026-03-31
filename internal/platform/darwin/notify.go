// internal/platform/darwin/notify.go
//go:build darwin

package darwin

/*
#include <notify.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// PolicyUpdatedNotification is the Darwin notification name posted when
// policy changes. The Swift SysExt listens for this to refresh its cache.
const PolicyUpdatedNotification = "ai.canyonroad.agentsh.policy-updated"

// NotifyPolicyUpdated posts a Darwin notification to signal the SysExt
// that the policy cache should be refreshed. This is a fire-and-forget
// signal — the SysExt fetches the actual data via XPC.
func NotifyPolicyUpdated() {
	cname := C.CString(PolicyUpdatedNotification)
	defer C.free(unsafe.Pointer(cname))
	C.notify_post(cname)
}
