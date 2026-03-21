//go:build linux

package linux

import (
	"context"
	"fmt"
	"log/slog"
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
	mountMethod    string // "fusermount", "new-api", "direct", ""
	mu             sync.Mutex
	mounts         map[string]*Mount
}

// NewFilesystem creates a new Linux filesystem interceptor.
func NewFilesystem() *Filesystem {
	fs := &Filesystem{
		mounts: make(map[string]*Mount),
	}
	fs.mountMethod = detectMountMethod()
	fs.available = fs.mountMethod != ""
	fs.implementation = fs.detectImplementation()
	return fs
}

// checkAvailable checks if FUSE is available and mountable.
func (fs *Filesystem) checkAvailable() bool {
	fs.mountMethod = detectMountMethod()
	return fs.mountMethod != ""
}

// detectMountMethod determines which FUSE mount strategy is available.
// Tries: fusermount → new mount API → direct mount().
func detectMountMethod() string {
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR, 0)
	if err != nil {
		slog.Debug("fuse: /dev/fuse not available", "error", err)
		return ""
	}
	unix.Close(fd)

	if hasFusermount() {
		slog.Info("fuse: mount method selected", "method", "fusermount")
		return "fusermount"
	}
	slog.Debug("fuse: fusermount not found, trying new mount API")

	if checkNewMountAPI() {
		slog.Info("fuse: mount method selected", "method", "new-api")
		return "new-api"
	}
	slog.Debug("fuse: new mount API not available, trying direct mount")

	if checkDirectMount() {
		slog.Info("fuse: mount method selected", "method", "direct")
		return "direct"
	}
	slog.Debug("fuse: no mount method available")

	return ""
}

// checkNewMountAPI probes whether the new mount API works for FUSE.
func checkNewMountAPI() bool {
	fd, err := unix.Fsopen("fuse", 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// MountMethod returns the detected FUSE mount method.
func (fs *Filesystem) MountMethod() string {
	return fs.mountMethod
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

// mountFUSEViaNewAPI mounts a FUSE filesystem using the Linux new mount API
// (fsopen/fsconfig/fsmount/move_mount). Returns the /dev/fuse fd for go-fuse.
// The caller is responsible for closing the fd when the FUSE server shuts down.
func mountFUSEViaNewAPI(mountPoint string, allowOther bool, maxRead int) (fuseFD int, err error) {
	fuseDev, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/fuse: %w", err)
	}

	success := false
	defer func() {
		if !success {
			unix.Close(fuseDev)
		}
	}()

	fsctx, err := unix.Fsopen("fuse", 0)
	if err != nil {
		return -1, fmt.Errorf("fsopen fuse: %w", err)
	}
	defer unix.Close(fsctx)

	configs := []struct{ key, val string }{
		{"fd", fmt.Sprintf("%d", fuseDev)},
		{"rootmode", "40000"},
		{"user_id", fmt.Sprintf("%d", os.Geteuid())},
		{"group_id", fmt.Sprintf("%d", os.Getegid())},
	}
	if maxRead > 0 {
		configs = append(configs, struct{ key, val string }{"max_read", fmt.Sprintf("%d", maxRead)})
	}
	for _, c := range configs {
		if err := unix.FsconfigSetString(fsctx, c.key, c.val); err != nil {
			return -1, fmt.Errorf("fsconfig %s=%s: %w", c.key, c.val, err)
		}
	}
	if allowOther {
		if err := unix.FsconfigSetFlag(fsctx, "allow_other"); err != nil {
			return -1, fmt.Errorf("fsconfig allow_other: %w", err)
		}
	}

	if err := unix.FsconfigCreate(fsctx); err != nil {
		return -1, fmt.Errorf("fsconfig create: %w", err)
	}

	mntFD, err := unix.Fsmount(fsctx, 0, 0)
	if err != nil {
		return -1, fmt.Errorf("fsmount: %w", err)
	}
	defer unix.Close(mntFD)

	if err := unix.MoveMount(mntFD, "", unix.AT_FDCWD, mountPoint, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return -1, fmt.Errorf("move_mount to %s: %w", mountPoint, err)
	}

	success = true
	return fuseDev, nil
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
		SessionID:   cfg.SessionID,
		VirtualRoot: cfg.VirtualRoot,
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
				Mode:      "soft_delete",
				TrashPath: cfg.TrashConfig.TrashDir,
			},
			HashLimitBytes:   cfg.TrashConfig.HashLimitBytes,
			NotifySoftDelete: cfg.NotifySoftDelete,
		}
	}

	// Create the FUSE mount using existing fsmonitor with a timeout
	// to prevent hanging if mount is blocked (e.g., by seccomp)
	effectiveMountPoint := cfg.MountPoint
	mountedViaNewAPI := false
	fuseFD := -1

	if fs.mountMethod == "new-api" {
		var err error
		fuseFD, err = mountFUSEViaNewAPI(cfg.MountPoint, true, 0)
		if err != nil {
			return nil, fmt.Errorf("new mount API failed: %w", err)
		}
		effectiveMountPoint = fmt.Sprintf("/dev/fd/%d", fuseFD)
		mountedViaNewAPI = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fsMount, err := fsmonitor.MountWorkspace(ctx, cfg.SourcePath, effectiveMountPoint, hooks)
	if err != nil {
		if mountedViaNewAPI {
			unix.Unmount(cfg.MountPoint, 0)
			unix.Close(fuseFD)
		}
		return nil, fmt.Errorf("failed to mount FUSE filesystem: %w", err)
	}

	// Wrap in our Mount type
	mount := &Mount{
		fsMount:          fsMount,
		sourcePath:       cfg.SourcePath,
		mountPoint:       cfg.MountPoint, // always real path
		mountedAt:        time.Now(),
		hooks:            hooks,
		mountedViaNewAPI: mountedViaNewAPI,
		fuseFD:           fuseFD,
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

	if m.mountedViaNewAPI {
		err := unix.Unmount(m.mountPoint, 0)
		if m.fuseFD >= 0 {
			unix.Close(m.fuseFD)
			m.fuseFD = -1
		}
		return err
	}
	return m.fsMount.Unmount()
}

// Mount wraps fsmonitor.Mount to implement platform.FSMount.
type Mount struct {
	fsMount          *fsmonitor.Mount
	sourcePath       string
	mountPoint       string
	mountedAt        time.Time
	hooks            *fsmonitor.Hooks
	mountedViaNewAPI bool // true if mounted via new mount API
	fuseFD           int  // /dev/fuse fd to close on unmount (new-api only, -1 if unused)

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
	if m.mountedViaNewAPI {
		err := unix.Unmount(m.mountPoint, 0)
		if m.fuseFD >= 0 {
			unix.Close(m.fuseFD)
			m.fuseFD = -1
		}
		return err
	}
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
