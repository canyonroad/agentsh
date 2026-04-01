//go:build darwin && cgo

package darwin

/*
#include <notify.h>
#include <stdlib.h>
*/
import "C"

import (
	"log/slog"
	"unsafe"
)

// PolicyUpdatedNotification is the Darwin notification name posted when
// policy changes. The Swift SysExt listens for this to refresh its cache.
const PolicyUpdatedNotification = "ai.canyonroad.agentsh.policy-updated"

// NotifyPolicyUpdated posts a Darwin notification to signal the SysExt
// that the policy cache should be refreshed. This is a fire-and-forget
// signal — the SysExt fetches the actual data via XPC.
func NotifyPolicyUpdated() {
	cname := C.CString(PolicyUpdatedNotification)
	defer C.free(unsafe.Pointer(cname))
	status := C.notify_post(cname)
	if status != 0 {
		// notify_post returns non-zero on failure (NOTIFY_STATUS_FAILED, etc.)
		slog.Warn("notify_post failed", "status", int(status), "name", PolicyUpdatedNotification)
	}
}
