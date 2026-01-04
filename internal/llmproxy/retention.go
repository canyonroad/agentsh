package llmproxy

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RetentionConfig configures session cleanup policy.
type RetentionConfig struct {
	MaxAgeDays int    // Delete sessions older than this (0 = disabled)
	MaxSizeMB  int    // Max total storage size in MB (0 = disabled)
	Eviction   string // "oldest_first" or "largest_first"
}

// RetentionResult reports cleanup results.
type RetentionResult struct {
	SessionsRemoved int
	BytesReclaimed  int64
	Sessions        []string // IDs of removed sessions
}

// sessionInfo holds metadata about a session directory.
type sessionInfo struct {
	ID      string
	Path    string
	Size    int64
	ModTime time.Time
}

// RunRetention cleans up old sessions based on retention policy.
// currentSessionID is excluded from cleanup.
// Runs synchronously - caller should use goroutine if non-blocking behavior is needed.
func RunRetention(
	sessionsDir string,
	config RetentionConfig,
	currentSessionID string,
	logger *slog.Logger,
) (*RetentionResult, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Skip if no retention configured
	if config.MaxAgeDays <= 0 && config.MaxSizeMB <= 0 {
		return &RetentionResult{}, nil
	}

	logger.Info("retention cleanup started", "sessions_dir", sessionsDir)

	// List all session directories
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &RetentionResult{}, nil
		}
		return nil, err
	}

	// Build session info list
	var sessions []sessionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sessionID := entry.Name()

		// Skip current active session
		if sessionID == currentSessionID {
			continue
		}

		sessionPath := filepath.Join(sessionsDir, sessionID)
		info, err := entry.Info()
		if err != nil {
			logger.Warn("failed to get session info", "session_id", sessionID, "error", err)
			continue
		}

		size, err := dirSize(sessionPath)
		if err != nil {
			logger.Warn("failed to calculate session size", "session_id", sessionID, "error", err)
			size = 0
		}

		sessions = append(sessions, sessionInfo{
			ID:      sessionID,
			Path:    sessionPath,
			Size:    size,
			ModTime: info.ModTime(),
		})
	}

	if len(sessions) == 0 {
		logger.Info("retention cleanup complete", "removed", 0, "reclaimed_mb", 0)
		return &RetentionResult{}, nil
	}

	result := &RetentionResult{}
	now := time.Now()

	// Track which sessions to remove
	toRemove := make(map[string]string) // sessionID -> reason

	// Age-based cleanup
	if config.MaxAgeDays > 0 {
		maxAge := time.Duration(config.MaxAgeDays) * 24 * time.Hour
		cutoff := now.Add(-maxAge)

		for _, s := range sessions {
			if s.ModTime.Before(cutoff) {
				ageDays := int(now.Sub(s.ModTime).Hours() / 24)
				toRemove[s.ID] = "age"
				logger.Info("session marked for eviction",
					"session_id", s.ID,
					"reason", "age",
					"age_days", ageDays,
				)
			}
		}
	}

	// Calculate remaining sessions and total size
	var remaining []sessionInfo
	var totalSize int64
	for _, s := range sessions {
		if _, marked := toRemove[s.ID]; !marked {
			remaining = append(remaining, s)
			totalSize += s.Size
		}
	}

	// Size-based cleanup
	if config.MaxSizeMB > 0 {
		maxBytes := int64(config.MaxSizeMB) * 1024 * 1024

		if totalSize > maxBytes {
			// Sort remaining sessions by eviction strategy
			sortSessionsForEviction(remaining, config.Eviction)

			// Remove sessions until under quota
			for _, s := range remaining {
				if totalSize <= maxBytes {
					break
				}
				toRemove[s.ID] = "size"
				totalSize -= s.Size
				sizeMB := float64(s.Size) / (1024 * 1024)
				logger.Info("session marked for eviction",
					"session_id", s.ID,
					"reason", "size",
					"size_mb", sizeMB,
				)
			}
		}
	}

	// Perform removal
	for _, s := range sessions {
		reason, marked := toRemove[s.ID]
		if !marked {
			continue
		}

		if err := os.RemoveAll(s.Path); err != nil {
			logger.Error("failed to remove session",
				"session_id", s.ID,
				"reason", reason,
				"error", err,
			)
			continue
		}

		result.SessionsRemoved++
		result.BytesReclaimed += s.Size
		result.Sessions = append(result.Sessions, s.ID)
	}

	reclaimedMB := float64(result.BytesReclaimed) / (1024 * 1024)
	logger.Info("retention cleanup complete",
		"removed", result.SessionsRemoved,
		"reclaimed_mb", reclaimedMB,
	)

	return result, nil
}

// sortSessionsForEviction sorts sessions based on eviction strategy.
func sortSessionsForEviction(sessions []sessionInfo, strategy string) {
	switch strategy {
	case "largest_first":
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].Size > sessions[j].Size
		})
	default: // "oldest_first"
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].ModTime.Before(sessions[j].ModTime)
		})
	}
}

// dirSize calculates the total size of a directory.
func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}
