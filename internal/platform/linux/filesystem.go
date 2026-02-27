//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/fsmonitor"
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/trash"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

// Filesystem implements platform.FilesystemInterceptor for Linux using FUSE.
type Filesystem struct {
	available      bool
	implementation string
	mu             sync.Mutex
	mounts         map[string]*Mount
}

// NewFilesystem creates a new Linux filesystem interceptor.
func NewFilesystem() *Filesystem {
	fs := &Filesystem{
		mounts: make(map[string]*Mount),
	}
	fs.available = fs.checkAvailable()
	fs.implementation = fs.detectImplementation()
	return fs
}

// checkAvailable checks if FUSE is available and mountable.
func (fs *Filesystem) checkAvailable() bool {
	return canMountFUSE()
}

// canMountFUSE checks if FUSE can actually be mounted by verifying:
// 1. /dev/fuse can be opened with O_RDWR
// 2. fusermount suid binary is available (preferred), OR
// 3. The process has CAP_SYS_ADMIN and mount() is not blocked by seccomp (fallback)
func canMountFUSE() bool {
	// Check that /dev/fuse can be opened (not just that it exists)
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)

	// Preferred path: check if fusermount is available.
	// Since agentsh uses go-fuse without DirectMount, it will use the fusermount
	// suid binary which handles mount() in its own privileged context. This works
	// even when the calling process lacks CAP_SYS_ADMIN or seccomp blocks mount().
	if hasFusermount() {
		return true
	}

	// Fallback: check for direct mount capability (CAP_SYS_ADMIN + mount probe).
	return checkDirectMount()
}

// hasFusermount checks if the fusermount suid binary is available in PATH.
func hasFusermount() bool {
	for _, name := range []string{"fusermount3", "fusermount"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

// checkDirectMount checks if direct mount() is possible (CAP_SYS_ADMIN + unblocked syscall).
func checkDirectMount() bool {
	// Check for CAP_SYS_ADMIN in the effective capability set.
	// The mount() syscall requires this capability.
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := &unix.CapUserData{}
	if err := unix.Capget(hdr, data); err != nil {
		return false
	}
	const capSysAdmin = unix.CAP_SYS_ADMIN // capability 21
	if data.Effective&(1<<uint(capSysAdmin)) == 0 {
		return false
	}

	// Probe mount() syscall to detect seccomp blocking.
	return probeMountSyscall()
}

// probeMountSyscall attempts a harmless mount() call with invalid parameters
// to detect whether seccomp is blocking the syscall.
// Returns true if mount() is allowed (even though it fails with expected errors).
func probeMountSyscall() bool {
	type result struct {
		err error
	}
	ch := make(chan result, 1)
	go func() {
		err := unix.Mount("", "", "agentsh-probe", 0, "")
		ch <- result{err: err}
	}()

	select {
	case r := <-ch:
		// EPERM with CAP_SYS_ADMIN means seccomp is blocking mount()
		if r.err == unix.EPERM {
			return false
		}
		// ENODEV, EINVAL, etc. = mount syscall is allowed (just bad params)
		return true
	case <-time.After(500 * time.Millisecond):
		// Timed out — mount() is blocked/hanging
		return false
	}
}

// detectImplementation returns the FUSE version.
func (fs *Filesystem) detectImplementation() string {
	// The go-fuse library we use supports FUSE2 and FUSE3
	// Check kernel support
	data, err := os.ReadFile("/proc/filesystems")
	if err == nil {
		if contains(string(data), "fuse") {
			return "fuse3" // go-fuse uses FUSE3 API when available
		}
	}
	return "fuse2"
}

// Available returns whether FUSE is available.
func (fs *Filesystem) Available() bool {
	return fs.available
}

// Recheck re-probes FUSE availability and implementation.
// This is used for deferred FUSE mounting where /dev/fuse permissions
// may change after initial startup (e.g., in E2B sandbox environments).
func (fs *Filesystem) Recheck() {
	fs.available = fs.checkAvailable()
	if fs.available && fs.implementation == "" {
		fs.implementation = fs.detectImplementation()
	}
}

// Implementation returns the FUSE implementation name.
func (fs *Filesystem) Implementation() string {
	return fs.implementation
}

// Mount creates a new FUSE mount with interception enabled.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("FUSE not available: /dev/fuse not found")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check if already mounted
	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// Create the fsmonitor hooks
	// This bridges the new platform.FSConfig to the existing fsmonitor.Hooks
	hooks := &fsmonitor.Hooks{
		SessionID: cfg.SessionID,
		// Policy will be wrapped from cfg.PolicyEngine
		Policy: wrapPolicyEngine(cfg.PolicyEngine),
		// Event emission bridged to cfg.EventChannel
		Emit: &eventEmitter{
			eventChan:     cfg.EventChannel,
			sessionID:     cfg.SessionID,
			commandIDFunc: cfg.CommandIDFunc,
		},
		TraceContextFunc: cfg.TraceContextFunc,
	}

	// Set up trash/soft-delete if configured
	if cfg.TrashConfig != nil && cfg.TrashConfig.Enabled {
		hooks.FUSEAudit = &fsmonitor.FUSEAuditHooks{
			Config: config.FUSEAuditConfig{
				Mode: "soft_delete",
			},
			HashLimitBytes:   cfg.TrashConfig.HashLimitBytes,
			NotifySoftDelete: cfg.NotifySoftDelete,
		}
	}

	// Create the FUSE mount using existing fsmonitor with a timeout
	// to prevent hanging if mount is blocked (e.g., by seccomp)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fsMount, err := fsmonitor.MountWorkspace(ctx, cfg.SourcePath, cfg.MountPoint, hooks)
	if err != nil {
		return nil, fmt.Errorf("failed to mount FUSE filesystem: %w", err)
	}

	// Wrap in our Mount type
	mount := &Mount{
		fsMount:    fsMount,
		sourcePath: cfg.SourcePath,
		mountPoint: cfg.MountPoint,
		mountedAt:  time.Now(),
		hooks:      hooks,
	}

	fs.mounts[cfg.MountPoint] = mount

	return mount, nil
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*Mount)
	if !ok {
		return fmt.Errorf("invalid mount type: expected *linux.Mount")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, m.mountPoint)

	return m.fsMount.Unmount()
}

// Mount wraps fsmonitor.Mount to implement platform.FSMount.
type Mount struct {
	fsMount    *fsmonitor.Mount
	sourcePath string
	mountPoint string
	mountedAt  time.Time
	hooks      *fsmonitor.Hooks

	// Stats tracking
	mu            sync.Mutex
	totalOps      int64
	allowedOps    int64
	deniedOps     int64
	redirectedOps int64
	bytesRead     int64
	bytesWritten  int64
}

// Path returns the mount point path.
func (m *Mount) Path() string {
	return m.mountPoint
}

// SourcePath returns the underlying real filesystem path.
func (m *Mount) SourcePath() string {
	return m.sourcePath
}

// Stats returns current mount statistics.
func (m *Mount) Stats() platform.FSStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	return platform.FSStats{
		MountedAt:     m.mountedAt,
		TotalOps:      m.totalOps,
		AllowedOps:    m.allowedOps,
		DeniedOps:     m.deniedOps,
		RedirectedOps: m.redirectedOps,
		BytesRead:     m.bytesRead,
		BytesWritten:  m.bytesWritten,
	}
}

// Close unmounts the filesystem.
func (m *Mount) Close() error {
	return m.fsMount.Unmount()
}

// eventEmitter bridges platform.EventChannel to fsmonitor.Emitter.
type eventEmitter struct {
	eventChan     chan<- platform.IOEvent
	sessionID     string
	commandIDFunc func() string
}

// AppendEvent implements fsmonitor.Emitter.
func (e *eventEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	if e.eventChan == nil {
		return nil
	}

	// Use session/command from config if not in event
	sessionID := ev.SessionID
	if sessionID == "" {
		sessionID = e.sessionID
	}
	commandID := ev.CommandID
	if commandID == "" && e.commandIDFunc != nil {
		commandID = e.commandIDFunc()
	}

	// Convert types.Event to platform.IOEvent
	ioEvent := platform.IOEvent{
		Timestamp:  ev.Timestamp,
		SessionID:  sessionID,
		CommandID:  commandID,
		Type:       platform.EventType(ev.Type),
		Path:       ev.Path,
		Domain:     ev.Domain,
		RemoteAddr: ev.Remote,
		Operation:  platform.FileOperation(ev.Operation),
		ProcessID:  ev.PID,
		Platform:   "linux-fuse3",
	}

	// Extract decision from policy info
	if ev.Policy != nil {
		ioEvent.Decision = ev.Policy.EffectiveDecision
		ioEvent.PolicyRule = ev.Policy.Rule
	}

	// Non-blocking send
	select {
	case e.eventChan <- ioEvent:
	default:
		// Channel full, drop event
	}

	return nil
}

// Publish implements fsmonitor.Emitter.
// No-op: AppendEvent already sends to the event channel, and processIOEvents
// handles both store.AppendEvent and broker.Publish on the receiving end.
func (e *eventEmitter) Publish(ev types.Event) {}

// wrapPolicyEngine extracts *policy.Engine from platform.PolicyEngine.
// If the PolicyEngine is a *PolicyAdapter, it returns the underlying engine.
// Otherwise returns nil (allowing all operations).
func wrapPolicyEngine(pe platform.PolicyEngine) *policy.Engine {
	if pe == nil {
		return nil
	}
	// Check if it's a PolicyAdapter wrapping *policy.Engine
	if adapter, ok := pe.(*platform.PolicyAdapter); ok {
		return adapter.Engine()
	}
	// For other implementations, we can't extract the engine
	// The platform interface will be used directly in the future
	return nil
}

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Compile-time interface checks
var (
	_ platform.FilesystemInterceptor = (*Filesystem)(nil)
	_ platform.FSMount               = (*Mount)(nil)
	_ fsmonitor.Emitter              = (*eventEmitter)(nil)
)

// Ensure trash package is imported for soft-delete functionality
var _ = trash.Entry{}
