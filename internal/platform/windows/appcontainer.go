//go:build windows

package windows

import (
	"fmt"
	"regexp"
	"sync"

	"golang.org/x/sys/windows"
)

// appContainer wraps Windows AppContainer APIs for process isolation.
type appContainer struct {
	name        string       // Container profile name
	sid         *windows.SID // Container security identifier
	grantedACLs []string     // Paths we modified (for cleanup)
	mu          sync.Mutex
	created     bool
}

// invalidChars matches characters not allowed in AppContainer names
var invalidChars = regexp.MustCompile(`[/\\:*?"<>|]`)

// appContainerName generates a valid AppContainer profile name from a sandbox ID.
func appContainerName(sandboxID string) string {
	// Sanitize the ID for use in registry key names
	sanitized := invalidChars.ReplaceAllString(sandboxID, "-")
	return fmt.Sprintf("agentsh-sandbox-%s", sanitized)
}

// newAppContainer creates a new appContainer wrapper.
// Does NOT create the profile yet - call create() for that.
func newAppContainer(sandboxID string) *appContainer {
	return &appContainer{
		name:        appContainerName(sandboxID),
		grantedACLs: make([]string, 0),
	}
}
