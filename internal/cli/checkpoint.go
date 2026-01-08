package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/spf13/cobra"
)

func newCheckpointCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checkpoint",
		Short: "Manage workspace checkpoints for rollback",
	}
	cmd.AddCommand(
		newCheckpointCreateCmd(),
		newCheckpointListCmd(),
		newCheckpointShowCmd(),
		newCheckpointRollbackCmd(),
		newCheckpointPurgeCmd(),
	)
	return cmd
}

func addCheckpointStorageFlag(cmd *cobra.Command) {
	cmd.Flags().String("storage-dir", "", "checkpoint storage directory (default: config sessions.checkpoints.storage_dir)")
}

func getCheckpointStorage(cmd *cobra.Command) (*session.FileCheckpointStorage, error) {
	dir, _ := cmd.Flags().GetString("storage-dir")
	if dir == "" {
		dir = "/var/lib/agentsh/checkpoints"
	}
	return session.NewFileCheckpointStorage(dir, 0)
}

func newCheckpointCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a checkpoint for a session",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, _ := cmd.Flags().GetString("session")
			reason, _ := cmd.Flags().GetString("reason")
			workspace, _ := cmd.Flags().GetString("workspace")

			if sessionID == "" {
				return fmt.Errorf("--session is required")
			}
			if workspace == "" {
				return fmt.Errorf("--workspace is required")
			}

			storage, err := getCheckpointStorage(cmd)
			if err != nil {
				return fmt.Errorf("init storage: %w", err)
			}

			manager := session.NewCheckpointManager(storage)

			// Create a minimal session object for checkpoint creation
			sess := &session.Session{
				ID:        sessionID,
				Workspace: workspace,
			}

			cp, err := manager.CreateCheckpointWithSnapshot(sess, reason, nil)
			if err != nil {
				return fmt.Errorf("create checkpoint: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Created checkpoint %s\n", cp.ID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Session:     %s\n", cp.SessionID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Reason:      %s\n", cp.Reason)
			fmt.Fprintf(cmd.OutOrStdout(), "  Can rollback: %v\n", cp.CanRollback)
			fmt.Fprintf(cmd.OutOrStdout(), "  Created:     %s\n", cp.CreatedAt.Format(time.RFC3339))

			return nil
		},
	}
	addCheckpointStorageFlag(cmd)
	cmd.Flags().String("session", "", "session ID (required)")
	cmd.Flags().String("workspace", "", "workspace path (required)")
	cmd.Flags().String("reason", "manual checkpoint", "reason for checkpoint")
	return cmd
}

func newCheckpointListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List checkpoints for a session",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, _ := cmd.Flags().GetString("session")
			jsonOutput, _ := cmd.Flags().GetBool("json")

			if sessionID == "" {
				return fmt.Errorf("--session is required")
			}

			storage, err := getCheckpointStorage(cmd)
			if err != nil {
				return fmt.Errorf("init storage: %w", err)
			}

			manager := session.NewCheckpointManager(storage)
			checkpoints, err := manager.ListCheckpoints(sessionID)
			if err != nil {
				return fmt.Errorf("list checkpoints: %w", err)
			}

			if len(checkpoints) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No checkpoints found")
				return nil
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(checkpoints)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-36s  %-20s  %-10s  %s\n", "ID", "CREATED", "ROLLBACK", "REASON")
			for _, cp := range checkpoints {
				rollback := "no"
				if cp.CanRollback {
					rollback = "yes"
				}
				age := time.Since(cp.CreatedAt).Round(time.Second)
				fmt.Fprintf(cmd.OutOrStdout(), "%-36s  %-20s  %-10s  %s\n",
					cp.ID,
					age.String()+" ago",
					rollback,
					truncateStr(cp.Reason, 40),
				)
			}

			return nil
		},
	}
	addCheckpointStorageFlag(cmd)
	cmd.Flags().String("session", "", "session ID (required)")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func newCheckpointShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <checkpoint-id>",
		Short: "Show checkpoint details and optionally diff",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkpointID := args[0]
			sessionID, _ := cmd.Flags().GetString("session")
			workspace, _ := cmd.Flags().GetString("workspace")
			showDiff, _ := cmd.Flags().GetBool("diff")
			jsonOutput, _ := cmd.Flags().GetBool("json")

			if sessionID == "" {
				return fmt.Errorf("--session is required")
			}

			storage, err := getCheckpointStorage(cmd)
			if err != nil {
				return fmt.Errorf("init storage: %w", err)
			}

			manager := session.NewCheckpointManager(storage)
			meta, err := manager.GetCheckpointMetadata(sessionID, checkpointID)
			if err != nil {
				return fmt.Errorf("get checkpoint: %w", err)
			}

			if jsonOutput {
				output := map[string]interface{}{
					"checkpoint": meta,
				}

				if showDiff && workspace != "" {
					diffs, err := manager.Diff(sessionID, checkpointID, workspace)
					if err == nil {
						output["diff"] = diffs
					}
				}

				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(output)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Checkpoint: %s\n", meta.ID)
			fmt.Fprintf(cmd.OutOrStdout(), "Session:    %s\n", meta.SessionID)
			fmt.Fprintf(cmd.OutOrStdout(), "Created:    %s\n", meta.CreatedAt.Format(time.RFC3339))
			fmt.Fprintf(cmd.OutOrStdout(), "Reason:     %s\n", meta.Reason)
			fmt.Fprintf(cmd.OutOrStdout(), "Rollback:   %v\n", meta.CanRollback)

			if len(meta.Files) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\nFiles (%d):\n", len(meta.Files))
				for _, f := range meta.Files {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s (%d bytes)\n", f.Path, f.Size)
				}
			}

			if showDiff && workspace != "" {
				diffs, err := manager.Diff(sessionID, checkpointID, workspace)
				if err != nil {
					return fmt.Errorf("compute diff: %w", err)
				}

				if len(diffs) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "\nNo changes since checkpoint")
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "\nChanges since checkpoint (%d):\n", len(diffs))
					for _, d := range diffs {
						symbol := "?"
						switch d.Status {
						case "added":
							symbol = "+"
						case "modified":
							symbol = "M"
						case "deleted":
							symbol = "-"
						}
						fmt.Fprintf(cmd.OutOrStdout(), "  %s %s\n", symbol, d.Path)
					}
				}
			}

			return nil
		},
	}
	addCheckpointStorageFlag(cmd)
	cmd.Flags().String("session", "", "session ID (required)")
	cmd.Flags().String("workspace", "", "workspace path (for diff)")
	cmd.Flags().Bool("diff", false, "show diff against current workspace")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func newCheckpointRollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback <checkpoint-id>",
		Short: "Restore workspace to checkpoint state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkpointID := args[0]
			sessionID, _ := cmd.Flags().GetString("session")
			workspace, _ := cmd.Flags().GetString("workspace")
			dryRun, _ := cmd.Flags().GetBool("dry-run")

			if sessionID == "" {
				return fmt.Errorf("--session is required")
			}
			if workspace == "" {
				return fmt.Errorf("--workspace is required")
			}

			storage, err := getCheckpointStorage(cmd)
			if err != nil {
				return fmt.Errorf("init storage: %w", err)
			}

			manager := session.NewCheckpointManager(storage)

			// Show what would be restored
			diffs, err := manager.Diff(sessionID, checkpointID, workspace)
			if err != nil {
				return fmt.Errorf("compute diff: %w", err)
			}

			if len(diffs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No changes to rollback")
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Will restore %d files:\n", len(diffs))
			for _, d := range diffs {
				switch d.Status {
				case "modified":
					fmt.Fprintf(cmd.OutOrStdout(), "  M %s\n", d.Path)
				case "deleted":
					fmt.Fprintf(cmd.OutOrStdout(), "  + %s (restore deleted)\n", d.Path)
				case "added":
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s (file was added after checkpoint, will remain)\n", d.Path)
				}
			}

			if dryRun {
				fmt.Fprintln(cmd.OutOrStdout(), "\n(dry-run: no changes made)")
				return nil
			}

			// Perform rollback
			restored, err := manager.Rollback(sessionID, checkpointID, workspace)
			if err != nil {
				return fmt.Errorf("rollback: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nRolled back %d files\n", len(restored))

			return nil
		},
	}
	addCheckpointStorageFlag(cmd)
	cmd.Flags().String("session", "", "session ID (required)")
	cmd.Flags().String("workspace", "", "workspace path (required)")
	cmd.Flags().Bool("dry-run", false, "show what would be restored without making changes")
	return cmd
}

func newCheckpointPurgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Remove old checkpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, _ := cmd.Flags().GetString("session")
			olderThan, _ := cmd.Flags().GetString("older-than")
			keepCount, _ := cmd.Flags().GetInt("keep")

			if sessionID == "" {
				return fmt.Errorf("--session is required")
			}

			storage, err := getCheckpointStorage(cmd)
			if err != nil {
				return fmt.Errorf("init storage: %w", err)
			}

			manager := session.NewCheckpointManager(storage)

			var maxAge time.Duration
			if olderThan != "" {
				maxAge, err = time.ParseDuration(olderThan)
				if err != nil {
					return fmt.Errorf("parse --older-than: %w", err)
				}
			}

			deleted, err := manager.PurgeCheckpoints(sessionID, maxAge, keepCount)
			if err != nil {
				return fmt.Errorf("purge: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Purged %d checkpoints\n", deleted)

			return nil
		},
	}
	addCheckpointStorageFlag(cmd)
	cmd.Flags().String("session", "", "session ID (required)")
	cmd.Flags().String("older-than", "", "purge checkpoints older than duration (e.g., 24h)")
	cmd.Flags().Int("keep", 0, "keep only N most recent checkpoints (0 = no limit)")
	return cmd
}

// truncateStr truncates a string to max length with ellipsis
func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// resolveWorkspacePath resolves a workspace path, handling relative paths
func resolveWorkspacePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("workspace path is empty")
	}
	return filepath.Abs(path)
}
