//go:build linux

package landlock

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock syscall numbers
// Note: These are consistent across amd64 and arm64 (verified in Linux 5.13+).
// If golang.org/x/sys/unix exports these constants in a future version,
// prefer those for better portability.
const (
	SYS_LANDLOCK_CREATE_RULESET = 444
	SYS_LANDLOCK_ADD_RULE       = 445
	SYS_LANDLOCK_RESTRICT_SELF  = 446
)

// Landlock rule types
const (
	LANDLOCK_RULE_PATH_BENEATH = 1
	LANDLOCK_RULE_NET_PORT     = 2
)

// Landlock access rights for filesystem
const (
	LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
	LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
	LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
	LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
	LANDLOCK_ACCESS_FS_REMOVE_DIR  = 1 << 4
	LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
	LANDLOCK_ACCESS_FS_MAKE_CHAR   = 1 << 6
	LANDLOCK_ACCESS_FS_MAKE_DIR    = 1 << 7
	LANDLOCK_ACCESS_FS_MAKE_REG    = 1 << 8
	LANDLOCK_ACCESS_FS_MAKE_SOCK   = 1 << 9
	LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1 << 10
	LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 1 << 11
	LANDLOCK_ACCESS_FS_MAKE_SYM    = 1 << 12
	LANDLOCK_ACCESS_FS_REFER       = 1 << 13 // ABI v2
	LANDLOCK_ACCESS_FS_TRUNCATE    = 1 << 14 // ABI v3
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

// landlockPathBeneathAttr is the attribute for path rules.
type landlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFd      int32
	_             [4]byte // padding
}

// landlockNetPortAttr is the attribute for network port rules.
type landlockNetPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

// RulesetBuilder constructs a Landlock ruleset from paths.
type RulesetBuilder struct {
	abi          int
	workspace    string
	executePaths []string
	readPaths    []string
	writePaths   []string
	denyPaths    []string
	allowNetwork bool
	allowBind    bool
}

// NewRulesetBuilder creates a new ruleset builder for the given ABI version.
func NewRulesetBuilder(abi int) *RulesetBuilder {
	return &RulesetBuilder{
		abi:          abi,
		executePaths: make([]string, 0),
		readPaths:    make([]string, 0),
		writePaths:   make([]string, 0),
		denyPaths:    make([]string, 0),
	}
}

// SetWorkspace sets the workspace path (gets full read/write/execute access).
func (b *RulesetBuilder) SetWorkspace(path string) {
	b.workspace = path
}

// AddExecutePath adds a path where execution is allowed.
func (b *RulesetBuilder) AddExecutePath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}
	b.executePaths = append(b.executePaths, absPath)
	return nil
}

// AddReadPath adds a path where reading is allowed.
func (b *RulesetBuilder) AddReadPath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}
	b.readPaths = append(b.readPaths, absPath)
	return nil
}

// AddWritePath adds a path where writing is allowed.
func (b *RulesetBuilder) AddWritePath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}
	b.writePaths = append(b.writePaths, absPath)
	return nil
}

// AddDenyPath marks a path to be denied (by not adding it to the ruleset).
func (b *RulesetBuilder) AddDenyPath(path string) {
	b.denyPaths = append(b.denyPaths, path)
}

// SetNetworkAccess configures network restrictions (ABI v4+ only).
func (b *RulesetBuilder) SetNetworkAccess(allowConnect, allowBind bool) {
	b.allowNetwork = allowConnect
	b.allowBind = allowBind
}

// Build creates the Landlock ruleset and returns the fd.
func (b *RulesetBuilder) Build() (int, error) {
	// Build access masks based on ABI
	accessFS := b.buildFSAccessMask()

	attr := landlockRulesetAttr{
		AccessFS: accessFS,
	}

	// Add network handling for ABI v4+ ONLY if we want to restrict network access.
	// If both allowNetwork and allowBind are true, we don't add network to HandledAccessNet
	// because that would allow all network access (no restrictions).
	// We only handle network when we want to selectively allow/deny.
	restrictNetwork := b.abi >= 4 && (!b.allowNetwork || !b.allowBind)
	if restrictNetwork {
		attr.AccessNet = LANDLOCK_ACCESS_NET_BIND_TCP |
			LANDLOCK_ACCESS_NET_CONNECT_TCP
	}

	// Calculate size based on ABI version
	var attrSize uintptr
	if b.abi >= 4 && restrictNetwork {
		attrSize = unsafe.Sizeof(attr)
	} else {
		attrSize = unsafe.Sizeof(attr.AccessFS)
	}

	// Create the ruleset
	fd, _, errno := syscall.Syscall(
		SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		attrSize,
		0,
	)
	if errno != 0 {
		return -1, fmt.Errorf("landlock_create_ruleset: %v", errno)
	}
	rulesetFd := int(fd)

	// Add workspace rule (full access)
	if b.workspace != "" {
		if err := b.addPathRule(rulesetFd, b.workspace, accessFS); err != nil {
			unix.Close(rulesetFd)
			return -1, fmt.Errorf("add workspace rule: %w", err)
		}
	}

	// Add execute paths
	execAccess := uint64(LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR)
	for _, path := range b.executePaths {
		if b.isDenied(path) {
			continue
		}
		if err := b.addPathRule(rulesetFd, path, execAccess); err != nil {
			// Non-fatal: path might not exist
			continue
		}
	}

	// Add read paths
	readAccess := uint64(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
	for _, path := range b.readPaths {
		if b.isDenied(path) {
			continue
		}
		if err := b.addPathRule(rulesetFd, path, readAccess); err != nil {
			continue
		}
	}

	// Add write paths (includes read access — writable paths must also be readable,
	// e.g., to cat a file you just created, or for tools that read-then-write).
	writeAccess := uint64(LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_DIR)
	if b.abi >= 3 {
		writeAccess |= LANDLOCK_ACCESS_FS_TRUNCATE
	}
	for _, path := range b.writePaths {
		if b.isDenied(path) {
			continue
		}
		if err := b.addPathRule(rulesetFd, path, writeAccess); err != nil {
			continue
		}
	}

	// Add network rules (ABI v4+) only when restricting network
	// When restrictNetwork is true, we add rules for what we ALLOW
	if restrictNetwork {
		if b.allowNetwork {
			if err := b.addNetRule(rulesetFd, LANDLOCK_ACCESS_NET_CONNECT_TCP); err != nil {
				unix.Close(rulesetFd)
				return -1, fmt.Errorf("add network connect rule: %w", err)
			}
		}
		if b.allowBind {
			if err := b.addNetRule(rulesetFd, LANDLOCK_ACCESS_NET_BIND_TCP); err != nil {
				unix.Close(rulesetFd)
				return -1, fmt.Errorf("add network bind rule: %w", err)
			}
		}
	}

	return rulesetFd, nil
}

func (b *RulesetBuilder) buildFSAccessMask() uint64 {
	access := uint64(
		LANDLOCK_ACCESS_FS_EXECUTE |
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
			LANDLOCK_ACCESS_FS_MAKE_SYM)

	if b.abi >= 2 {
		access |= LANDLOCK_ACCESS_FS_REFER
	}
	if b.abi >= 3 {
		access |= LANDLOCK_ACCESS_FS_TRUNCATE
	}

	return access
}

// accessFile is the set of access rights valid for non-directory inodes.
// The kernel returns EINVAL if directory-only rights are passed for a file.
const accessFile = LANDLOCK_ACCESS_FS_EXECUTE |
	LANDLOCK_ACCESS_FS_WRITE_FILE |
	LANDLOCK_ACCESS_FS_READ_FILE |
	LANDLOCK_ACCESS_FS_TRUNCATE

func (b *RulesetBuilder) addPathRule(rulesetFd int, path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer unix.Close(fd)

	// For non-directory inodes (files, devices, pipes), strip directory-only
	// access rights. The kernel rejects rules with MAKE_REG, REMOVE_DIR, etc.
	// on non-directory paths with EINVAL.
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err == nil && stat.Mode&unix.S_IFDIR == 0 {
		access &= accessFile
	}

	pathBeneath := landlockPathBeneathAttr{
		AllowedAccess: access,
		ParentFd:      int32(fd),
	}

	_, _, errno := syscall.Syscall6(
		SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFd),
		LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&pathBeneath)),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule: %v", errno)
	}

	return nil
}

func (b *RulesetBuilder) addNetRule(rulesetFd int, access uint64) error {
	// IMPORTANT: Landlock network rules are PORT-SPECIFIC.
	// There is no way to allow "all ports" with a single rule.
	// Port 0 only allows binding to ephemeral ports (32768-60999), NOT all ports.
	//
	// For blanket allow-all network access, the solution is to NOT include
	// network access in HandledAccessNet at all (handled in Build()).
	//
	// This function adds a rule for port 0 which allows:
	// - For BIND: binding to ephemeral ports only
	// - For CONNECT: connecting to port 0 (rarely useful)
	//
	// For more granular control, we would need to iterate over specific ports.
	// This is a known limitation documented in security-modes.md.
	netAttr := landlockNetPortAttr{
		AllowedAccess: access,
		Port:          0,
	}

	_, _, errno := syscall.Syscall6(
		SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFd),
		LANDLOCK_RULE_NET_PORT,
		uintptr(unsafe.Pointer(&netAttr)),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule (net): %v", errno)
	}

	return nil
}

// isDenied checks if a path is in the deny list.
// LIMITATION: This check does not resolve symlinks. A symlink pointing to a
// denied path (e.g., /tmp/link -> /var/run/docker.sock) will not be caught.
// However, Landlock itself operates on the resolved path, so the actual
// protection is still in place - we just might add a rule for a symlink
// that won't be useful.
func (b *RulesetBuilder) isDenied(path string) bool {
	for _, deny := range b.denyPaths {
		if path == deny || strings.HasPrefix(path, deny+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// Enforce applies the ruleset to the current process.
func Enforce(rulesetFd int) error {
	// Set no_new_privs first (required)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}

	// Apply the ruleset
	_, _, errno := syscall.Syscall(
		SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFd),
		0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %v", errno)
	}

	return nil
}
