//go:build darwin

package api

import "github.com/agentsh/agentsh/internal/platform/darwin"

func notifySessionRegistered() {
	darwin.NotifySessionRegistered()
}
