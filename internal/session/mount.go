package session

import (
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)

// ResolvedMount represents an active mount with its loaded policy.
type ResolvedMount struct {
	Path         string         // Absolute path that was mounted
	Policy       string         // Policy name
	MountPoint   string         // Where FUSE mounted it
	PolicyEngine *policy.Engine // Loaded policy engine for this mount
	Unmount      func() error   // Function to unmount
}

// FindMount finds the mount that covers the given path using longest prefix match.
// Returns nil if no mount covers the path.
func FindMount(mounts []ResolvedMount, path string) *ResolvedMount {
	var best *ResolvedMount
	for i := range mounts {
		if strings.HasPrefix(path, mounts[i].Path) {
			// Ensure it's a proper path prefix (not just string prefix)
			if len(path) == len(mounts[i].Path) || mounts[i].Path == "/" || path[len(mounts[i].Path)] == '/' {
				if best == nil || len(mounts[i].Path) > len(best.Path) {
					best = &mounts[i]
				}
			}
		}
	}
	return best
}
