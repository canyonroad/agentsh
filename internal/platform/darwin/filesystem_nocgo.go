//go:build darwin && !cgo

package darwin

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// Mount creates a FUSE mount. Without CGO, this returns an error
// directing the user to use observation-only mode (FSEvents).
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	return nil, fmt.Errorf(
		"FUSE mounting requires CGO; build with CGO_ENABLED=1 or use observation-only mode (FSEvents). "+
			"FUSE-T detected: %s", fs.implementation)
}

// cgoEnabled reports whether CGO is available.
const cgoEnabled = false
