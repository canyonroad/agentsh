//go:build darwin && !cgo

package darwin

const PolicyUpdatedNotification = "ai.canyonroad.agentsh.policy-updated"

// NotifyPolicyUpdated is a no-op when CGO is disabled.
func NotifyPolicyUpdated() {}
