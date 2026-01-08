package session

import (
	"path/filepath"
	"strings"
)

// AutoCheckpointConfig holds configuration for automatic checkpointing.
type AutoCheckpointConfig struct {
	Enabled  bool
	Triggers []string // Command names that trigger auto-checkpoint
}

// AutoCheckpoint provides automatic checkpoint creation before risky commands.
type AutoCheckpoint struct {
	config  AutoCheckpointConfig
	manager *CheckpointManager
}

// NewAutoCheckpoint creates a new auto-checkpoint handler.
func NewAutoCheckpoint(cfg AutoCheckpointConfig, manager *CheckpointManager) *AutoCheckpoint {
	return &AutoCheckpoint{
		config:  cfg,
		manager: manager,
	}
}

// ShouldCheckpoint returns true if the command should trigger auto-checkpoint.
func (a *AutoCheckpoint) ShouldCheckpoint(command string, args []string) bool {
	if !a.config.Enabled || a.manager == nil {
		return false
	}

	// Get base command name
	base := filepath.Base(command)

	// Check against triggers
	for _, trigger := range a.config.Triggers {
		if matchesTrigger(base, trigger, args) {
			return true
		}
	}

	return false
}

// CreateAutoCheckpoint creates a checkpoint for the given session before command execution.
// Returns the checkpoint ID on success, or empty string if checkpoint was not created.
func (a *AutoCheckpoint) CreateAutoCheckpoint(s *Session, command string, args []string) (string, error) {
	if !a.ShouldCheckpoint(command, args) {
		return "", nil
	}

	reason := "auto:pre_command:" + filepath.Base(command)
	if len(args) > 0 {
		// Include first few args for context
		argPreview := strings.Join(args, " ")
		if len(argPreview) > 50 {
			argPreview = argPreview[:47] + "..."
		}
		reason += " " + argPreview
	}

	// Try to predict affected files based on command and args
	affectedFiles := predictAffectedFiles(s.Workspace, command, args)

	cp, err := a.manager.CreateCheckpointWithSnapshot(s, reason, affectedFiles)
	if err != nil {
		return "", err
	}

	return cp.ID, nil
}

// matchesTrigger checks if a command matches a trigger pattern.
func matchesTrigger(command, trigger string, args []string) bool {
	// Exact match
	if command == trigger {
		return true
	}

	// Handle common cases
	switch trigger {
	case "rm":
		return command == "rm" || command == "rmdir" || command == "unlink"
	case "mv":
		return command == "mv" || command == "rename"
	case "git reset":
		return command == "git" && len(args) > 0 && args[0] == "reset"
	case "git checkout":
		return command == "git" && len(args) > 0 && args[0] == "checkout"
	case "git clean":
		return command == "git" && len(args) > 0 && args[0] == "clean"
	case "git stash":
		return command == "git" && len(args) > 0 && (args[0] == "stash" && (len(args) < 2 || args[1] != "list"))
	}

	return false
}

// predictAffectedFiles attempts to predict which files will be affected by a command.
// Returns nil if prediction is not possible (triggers full workspace backup).
func predictAffectedFiles(workspace, command string, args []string) []string {
	base := filepath.Base(command)

	switch base {
	case "rm", "rmdir", "unlink":
		// Try to extract file paths from args
		return extractFilePaths(workspace, args)

	case "mv", "rename":
		// Source file only
		if len(args) > 0 {
			return extractFilePaths(workspace, args[:1])
		}

	case "git":
		if len(args) > 0 {
			switch args[0] {
			case "checkout", "reset":
				// If specific files are mentioned, use those
				// Otherwise, can't predict - return nil for full backup
				if len(args) > 2 && args[1] == "--" {
					return extractFilePaths(workspace, args[2:])
				}
				// Full backup for general git reset/checkout
				return nil
			}
		}
	}

	// Default: can't predict, return nil for full backup
	return nil
}

// extractFilePaths extracts file paths from command arguments.
// Filters out flags (starting with -) and returns paths relative to workspace.
func extractFilePaths(workspace string, args []string) []string {
	var paths []string
	for _, arg := range args {
		// Skip flags
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Convert to relative path if absolute
		if filepath.IsAbs(arg) {
			rel, err := filepath.Rel(workspace, arg)
			if err == nil && !strings.HasPrefix(rel, "..") {
				paths = append(paths, rel)
			}
		} else {
			paths = append(paths, arg)
		}
	}
	return paths
}

// DefaultAutoCheckpointTriggers returns the default list of commands that trigger auto-checkpoint.
func DefaultAutoCheckpointTriggers() []string {
	return []string{
		"rm",
		"mv",
		"git reset",
		"git checkout",
		"git clean",
		"git stash",
	}
}
