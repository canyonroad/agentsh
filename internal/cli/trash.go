package cli

import (
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/trash"
	"github.com/spf13/cobra"
)

func newTrashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trash",
		Short: "Manage diverted (soft-deleted) files",
	}
	cmd.AddCommand(newTrashListCmd(), newTrashRestoreCmd(), newTrashPurgeCmd())
	return cmd
}

func addTrashPathFlag(cmd *cobra.Command) {
	cmd.Flags().String("trash-path", ".agentsh_trash", "trash directory (default relative to CWD)")
}

func getTrashPath(cmd *cobra.Command) string {
	p, _ := cmd.Flags().GetString("trash-path")
	if p == "" {
		return ".agentsh_trash"
	}
	return p
}

func newTrashListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List diverted items in the trash",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, _ := cmd.Flags().GetString("session")
			entries, err := trash.List(getTrashPath(cmd))
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "trash empty")
				return nil
			}
			for _, e := range entries {
				if session != "" && e.Session != session {
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%d bytes\t%s ago\n", e.Token, e.OriginalPath, e.Size, time.Since(e.Created).Round(time.Second))
			}
			return nil
		},
	}
	addTrashPathFlag(cmd)
	cmd.Flags().String("session", "", "filter by session id")
	return cmd
}

func newTrashRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore <token>",
		Short: "Restore a diverted item by token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dest, _ := cmd.Flags().GetString("dest")
			force, _ := cmd.Flags().GetBool("force")
			path, err := trash.Restore(getTrashPath(cmd), args[0], dest, force)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "restored to %s\n", path)
			return nil
		},
	}
	addTrashPathFlag(cmd)
	cmd.Flags().String("dest", "", "override restore destination")
	cmd.Flags().Bool("force", false, "overwrite destination if it exists")
	return cmd
}

func newTrashPurgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Purge trash entries by TTL or quota",
		RunE: func(cmd *cobra.Command, args []string) error {
			ttlStr, _ := cmd.Flags().GetString("ttl")
			quotaStr, _ := cmd.Flags().GetString("quota")
			session, _ := cmd.Flags().GetString("session")

			var ttl time.Duration
			var err error
			if ttlStr != "" {
				ttl, err = time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("parse ttl: %w", err)
				}
			}
			var quota int64
			if quotaStr != "" {
				quota, err = config.ParseByteSize(quotaStr)
				if err != nil {
					return fmt.Errorf("parse quota: %w", err)
				}
			}

			removed, err := trash.Purge(getTrashPath(cmd), trash.PurgeOptions{
				TTL:        ttl,
				QuotaBytes: quota,
				Session:    session,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %d entr(y/ies)\n", removed)
			return nil
		},
	}
	addTrashPathFlag(cmd)
	cmd.Flags().String("ttl", "", "TTL (e.g. 7d, 24h); empty disables")
	cmd.Flags().String("quota", "", "Quota cap (e.g. 5GB); empty disables")
	cmd.Flags().String("session", "", "Only purge entries for a session")
	return cmd
}
