//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
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
	policy   FilePolicyChecker
	registry *MountRegistry
	emitter  Emitter
	enforce  bool
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

// Handle evaluates a file request against policy and returns the enforcement result.
//
// Routing logic:
//  1. No policy -> allow with "no_policy" event.
//  2. Path under FUSE mount -> audit-only (FUSE handles enforcement).
//  3. Otherwise -> full enforcement based on policy decision and enforce flag.
func (h *FileHandler) Handle(req FileRequest) FileResult {
	// 1. No policy configured — allow everything.
	if h.policy == nil {
		dec := FilePolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "no_policy",
		}
		h.emitFileEvent(req, dec, false, false)
		return FileResult{Action: ActionContinue}
	}

	// 2. Path under FUSE mount — audit-only; let FUSE handle enforcement.
	if h.registry != nil && h.registry.IsUnderFUSEMount(req.SessionID, req.Path) {
		dec := h.policy.CheckFile(req.Path, req.Operation)
		shadowDeny := dec.EffectiveDecision == "deny"
		h.emitFileEvent(req, dec, false, shadowDeny)
		return FileResult{Action: ActionContinue}
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
			h.emitFileEvent(req, dec, false, false)
			return FileResult{Action: ActionContinue}
		}
		// Enforced deny.
		h.emitFileEvent(req, dec, true, false)
		return FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}
	}

	// Allowed.
	h.emitFileEvent(req, dec, false, false)
	return FileResult{Action: ActionContinue}
}

// emitFileEvent emits a structured event for a file operation.
func (h *FileHandler) emitFileEvent(req FileRequest, dec FilePolicyDecision, blocked, shadowDeny bool) {
	if h.emitter == nil {
		return
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

	ev := types.Event{
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

	_ = h.emitter.AppendEvent(context.Background(), ev)
	h.emitter.Publish(ev)
}
