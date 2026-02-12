// internal/netmonitor/unix/mount_registry.go
package unix

import (
	"strings"
	"sync"
)

// MountRegistry tracks active FUSE mount source paths per session.
type MountRegistry struct {
	mu     sync.RWMutex
	mounts map[string][]string // sessionID -> list of source paths
}

// NewMountRegistry creates a new MountRegistry.
func NewMountRegistry() *MountRegistry {
	return &MountRegistry{
		mounts: make(map[string][]string),
	}
}

// Register adds a source path to the session's mount list.
func (r *MountRegistry) Register(sessionID, sourcePath string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.mounts[sessionID] = append(r.mounts[sessionID], sourcePath)
}

// Deregister removes a specific source path from the session's mount list.
// If the list becomes empty, the session key is deleted.
func (r *MountRegistry) Deregister(sessionID, sourcePath string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	paths := r.mounts[sessionID]
	for i, p := range paths {
		if p == sourcePath {
			// Remove element by swapping with last and truncating.
			paths[i] = paths[len(paths)-1]
			paths = paths[:len(paths)-1]
			break
		}
	}

	if len(paths) == 0 {
		delete(r.mounts, sessionID)
	} else {
		r.mounts[sessionID] = paths
	}
}

// IsUnderFUSEMount returns true if path is equal to or is a child of any
// registered FUSE mount source path for the given session. The path separator
// "/" is required after the mount prefix to avoid "/home/user/proj" matching
// "/home/user/project".
func (r *MountRegistry) IsUnderFUSEMount(sessionID, path string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, srcPath := range r.mounts[sessionID] {
		if path == srcPath || strings.HasPrefix(path, srcPath+"/") {
			return true
		}
	}
	return false
}
