//go:build darwin && cgo

package darwin

import "testing"

func TestNotifyPolicyUpdated(t *testing.T) {
	// notify_post returns 0 on success
	// This posts a notification that nobody is listening for — harmless
	NotifyPolicyUpdated()
	// If we get here without a crash/panic, the cgo bridge works
}

func TestNotifyName(t *testing.T) {
	if PolicyUpdatedNotification != "ai.canyonroad.agentsh.policy-updated" {
		t.Fatalf("unexpected notification name: %s", PolicyUpdatedNotification)
	}
}
