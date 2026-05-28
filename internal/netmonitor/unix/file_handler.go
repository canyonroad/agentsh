//go:build linux && cgo

package unix

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	sysunix "golang.org/x/sys/unix"
)

// FilePolicyChecker evaluates file policy decisions.
type FilePolicyChecker interface {
	CheckFile(path, operation string) FilePolicyDecision
}

// FilePolicyDecision represents a file policy check result.
type FilePolicyDecision struct {
	Decision          string
	EffectiveDecision string
	Rule              string
	Message           string
}

// FileRequest holds the parsed context for a file syscall notification.
type FileRequest struct {
	PID       int
	Syscall   int32
	Path      string
	Path2     string // second path for rename/link
	Operation string
	Flags     uint32
	Mode      uint32
	SessionID string
}

// FileResult holds the outcome of handling a file syscall.
type FileResult struct {
	Action string // ActionContinue or ActionDeny
	Errno  int32
}

// FileHandler processes file syscall notifications against policy.
type FileHandler struct {
	policy      FilePolicyChecker
	registry    *MountRegistry
	emitter     Emitter
	enforce     bool
	emulateOpen bool // When true, supervisor emulates openat via AddFD
}

// NewFileHandler creates a new FileHandler.
func NewFileHandler(policy FilePolicyChecker, registry *MountRegistry, emitter Emitter, enforce bool) *FileHandler {
	return &FileHandler{
		policy:   policy,
		registry: registry,
		emitter:  emitter,
		enforce:  enforce,
	}
}

// SetEmulateOpen enables or disables openat AddFD emulation.
func (h *FileHandler) SetEmulateOpen(v bool) {
	h.emulateOpen = v
}

// EmulateOpen returns whether AddFD emulation is active.
func (h *FileHandler) EmulateOpen() bool {
	return h.emulateOpen
}

// Handle evaluates a file request against policy and returns the enforcement result
// and an optional audit event. The caller is responsible for emitting the event.
//
// Routing logic:
//  1. No policy -> allow with "no_policy" event.
//  2. Path under FUSE mount -> audit-only (FUSE handles enforcement).
//  3. Otherwise -> full enforcement based on policy decision and enforce flag.
func (h *FileHandler) Handle(req FileRequest) (FileResult, *types.Event) {
	// 0. Pseudo-paths (pipe:[...], socket:[...], anon_inode:[...]) resolve
	//    from /proc/<pid>/fd/<N> for non-filesystem fds. They are not
	//    filesystem objects and cannot match path-based policy rules —
	//    allow unconditionally to avoid spurious denials.
	if req.Path != "" && !strings.HasPrefix(req.Path, "/") {
		return FileResult{Action: ActionContinue}, nil
	}

	// 1. No policy configured — allow everything.
	if h.policy == nil {
		dec := FilePolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "no_policy",
		}
		return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)
	}

	// Resolve /proc/self/fd/N, /proc/<pid>/fd/N, /dev/fd/N to actual target.
	// This prevents policy bypass by re-deriving paths from file descriptors.
	// Normalize both Path and Path2 (for rename/link dual-path syscalls).
	if resolved, wasProcFD := resolveProcFD(req.PID, req.Path); wasProcFD {
		req.Path = resolved
	}
	if req.Path2 != "" {
		if resolved, wasProcFD := resolveProcFD(req.PID, req.Path2); wasProcFD {
			req.Path2 = resolved
		}
	}

	// 2. Path under FUSE mount point — audit-only; FUSE handles enforcement.
	//    Only defers when the resolved syscall path is actually under a FUSE
	//    mount point (e.g., sessions/{id}/mount-0), not a source path.
	if h.registry != nil && h.registry.IsUnderFUSEMount(req.SessionID, req.Path) {
		dec := h.policy.CheckFile(req.Path, req.Operation)
		shadowDeny := dec.EffectiveDecision == "deny"
		return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, shadowDeny)
	}

	// 3. Full enforcement path.
	dec := h.policy.CheckFile(req.Path, req.Operation)

	// For dual-path syscalls (rename, link), also check the second path.
	if req.Path2 != "" {
		dec2 := h.policy.CheckFile(req.Path2, req.Operation)
		// If either path is denied, the combined decision is deny.
		if dec2.EffectiveDecision == "deny" {
			dec = dec2
		}
	}

	if dec.EffectiveDecision == "deny" {
		if !h.enforce {
			// Audit-only mode: log but allow.
			return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)
		}
		// #369 loader-safe guard: never DENY a read-only access to an essential
		// system/loader path when the denial came from a catch-all default rule.
		// A deny-by-default policy would otherwise make every dynamically-linked
		// program un-loadable under file_monitor — the loader reads
		// /etc/ld.so.cache and walks /lib, /usr, ... during startup, and those
		// opens fall through allow-system-read (its /lib/** globs don't match the
		// bare dirs) to the default-deny-files catch-all. The ptrace enforcer
		// effectively allows these, so file_monitor must too.
		//
		// Scoped to the catch-all rule ONLY: an operator's EXPLICIT deny rule on a
		// system subpath (e.g. `deny read /opt/app/secrets/**`) is still honored,
		// matching ptrace's first-match-explicit-deny semantics. Read-only only —
		// writes/creates/deletes to these paths stay enforced.
		if isDefaultDenyRule(dec.Rule) && isReadOnlyFileOp(req.Syscall, req.Flags) && isLoaderSafeSystemPath(req.Path) {
			slog.Debug("file_monitor: loader-safe read override (#369)",
				"path", req.Path, "operation", req.Operation, "policy_rule", dec.Rule, "session", req.SessionID)
			// shadowDeny=true records that policy said deny but we did not enforce.
			return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, true)
		}
		// Enforced deny.
		return FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}, h.buildFileEvent(req, dec, true, false)
	}

	// Allowed.
	return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)
}

// buildFileEvent builds a structured event for a file operation without emitting it.
func (h *FileHandler) buildFileEvent(req FileRequest, dec FilePolicyDecision, blocked, shadowDeny bool) *types.Event {
	if h.emitter == nil {
		return nil
	}

	action := "allowed"
	if blocked {
		action = "blocked"
	}

	fields := map[string]any{
		"syscall": fileSyscallName(req.Syscall),
	}
	if shadowDeny {
		fields["shadow_deny"] = true
	}
	if req.Path2 != "" {
		fields["path2"] = req.Path2
	}

	ev := &types.Event{
		ID:        fmt.Sprintf("file-%d-%d", req.PID, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "file_" + req.Operation,
		SessionID: req.SessionID,
		Source:    "seccomp",
		PID:       req.PID,
		Path:      req.Path,
		Operation: req.Operation,
		Policy: &types.PolicyInfo{
			Decision:          types.Decision(dec.Decision),
			EffectiveDecision: types.Decision(dec.EffectiveDecision),
			Rule:              dec.Rule,
			Message:           dec.Message,
		},
		EffectiveAction: action,
		Fields:          fields,
	}

	return ev
}

// loaderSafeReadPrefixes are system paths whose READ-ONLY access must never be
// denied: the dynamic loader and libc must read these to start any program
// (ld.so.cache/preload/conf, and the standard system library + binary trees the
// loader resolves through). This mirrors the established system-readonly path
// set and the ptrace enforcer's effective behavior (#369). Matching is
// exact-or-subtree, so "/lib" covers both the bare directory open the loader
// performs during search-path resolution and every file beneath it.
var loaderSafeReadPrefixes = []string{
	"/usr", "/lib", "/lib64", "/lib32", "/libx32", "/bin", "/sbin", "/opt",
	"/etc/ld.so.cache", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
}

// defaultDenyRuleNames are the catch-all "deny everything not explicitly
// allowed" rule names. The loader-safe override fires only when a loader read
// was denied by one of these — never by an operator's explicit deny rule
// targeting a specific path, which must still be honored (matching the ptrace
// enforcer's first-match-explicit-deny semantics). "default-deny-files" is both
// the shipped policies' catch-all rule name and the engine's no-match fallback.
var defaultDenyRuleNames = map[string]bool{
	"default-deny-files": true,
}

// isDefaultDenyRule reports whether a deny decision came from a catch-all
// default rule rather than an explicit, path-specific operator deny.
func isDefaultDenyRule(rule string) bool { return defaultDenyRuleNames[rule] }

// isLoaderSafeSystemPath reports whether p is one of the loader-essential system
// paths (exact match or a subtree element).
func isLoaderSafeSystemPath(p string) bool {
	for _, pre := range loaderSafeReadPrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}
