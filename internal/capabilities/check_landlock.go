//go:build linux

package capabilities

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock syscall numbers (for amd64)
const (
	SYS_LANDLOCK_CREATE_RULESET = 444
	SYS_LANDLOCK_ADD_RULE       = 445
	SYS_LANDLOCK_RESTRICT_SELF  = 446
)

// Landlock access rights for filesystem (ABI v1)
const (
	LANDLOCK_ACCESS_FS_EXECUTE    = 1 << 0
	LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
	LANDLOCK_ACCESS_FS_READ_FILE  = 1 << 2
	LANDLOCK_ACCESS_FS_READ_DIR   = 1 << 3
	LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
	LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
	LANDLOCK_ACCESS_FS_MAKE_CHAR  = 1 << 6
	LANDLOCK_ACCESS_FS_MAKE_DIR   = 1 << 7
	LANDLOCK_ACCESS_FS_MAKE_REG   = 1 << 8
	LANDLOCK_ACCESS_FS_MAKE_SOCK  = 1 << 9
	LANDLOCK_ACCESS_FS_MAKE_FIFO  = 1 << 10
	LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
	LANDLOCK_ACCESS_FS_MAKE_SYM   = 1 << 12
	// ABI v2
	LANDLOCK_ACCESS_FS_REFER = 1 << 13
	// ABI v3
	LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
)

// Landlock access rights for network (ABI v4)
const (
	LANDLOCK_ACCESS_NET_BIND_TCP    = 1 << 0
	LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
)

// landlockRulesetAttr is the attribute structure for landlock_create_ruleset.
type landlockRulesetAttr struct {
	AccessFS  uint64
	AccessNet uint64
}

// LandlockResult holds the result of Landlock availability detection.
type LandlockResult struct {
	Available      bool
	ABI            int
	NetworkSupport bool
	Error          string
}

func (r LandlockResult) String() string {
	if !r.Available {
		return fmt.Sprintf("Landlock: unavailable (%s)", r.Error)
	}
	features := []string{fmt.Sprintf("ABI v%d", r.ABI)}
	if r.NetworkSupport {
		features = append(features, "network support")
	}
	return fmt.Sprintf("Landlock: available (%s)", strings.Join(features, ", "))
}

// DetectLandlock checks if Landlock is available and returns capability info.
func DetectLandlock() LandlockResult {
	// Try to detect highest supported ABI version
	for abi := 5; abi >= 1; abi-- {
		if tryLandlockABI(abi) {
			return LandlockResult{
				Available:      true,
				ABI:            abi,
				NetworkSupport: abi >= 4,
			}
		}
	}

	return LandlockResult{
		Available: false,
		Error:     "kernel does not support Landlock or it is disabled",
	}
}

func tryLandlockABI(abi int) bool {
	// Build access mask for this ABI version
	var accessFS uint64

	// ABI v1 access rights
	accessFS = LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_CHAR |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_SOCK |
		LANDLOCK_ACCESS_FS_MAKE_FIFO |
		LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		LANDLOCK_ACCESS_FS_MAKE_SYM

	if abi >= 2 {
		accessFS |= LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		accessFS |= LANDLOCK_ACCESS_FS_TRUNCATE
	}

	attr := landlockRulesetAttr{
		AccessFS: accessFS,
	}

	// Add network access for ABI v4+
	if abi >= 4 {
		attr.AccessNet = LANDLOCK_ACCESS_NET_BIND_TCP |
			LANDLOCK_ACCESS_NET_CONNECT_TCP
	}

	// Calculate size based on ABI version
	var attrSize uintptr
	if abi >= 4 {
		// Full struct with network support
		attrSize = unsafe.Sizeof(attr)
	} else {
		// Only AccessFS field for ABI v1-v3
		attrSize = unsafe.Sizeof(attr.AccessFS)
	}

	fd, _, errno := syscall.Syscall(
		SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		attrSize,
		0, // flags
	)

	if errno != 0 {
		return false
	}

	unix.Close(int(fd))
	return true
}
