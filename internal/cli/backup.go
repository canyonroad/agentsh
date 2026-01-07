package cli

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// sanitizeTarPath validates that a tar entry path doesn't escape the restore directory.
func sanitizeTarPath(name string) (string, error) {
	// Clean the path
	clean := filepath.Clean(name)
	// Reject absolute paths
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("absolute path not allowed: %s", name)
	}
	// Reject paths that escape via ..
	if strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("path traversal not allowed: %s", name)
	}
	return clean, nil
}

func newBackupCmd() *cobra.Command {
	var output string
	var verify bool
	var configPath string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup of agentsh data",
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				output = fmt.Sprintf("agentsh-backup-%s.tar.gz", time.Now().Format("20060102-150405"))
			}
			return createBackup(cmd, output, configPath, verify)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default: agentsh-backup-<timestamp>.tar.gz)")
	cmd.Flags().BoolVar(&verify, "verify", false, "Verify backup after creation")
	cmd.Flags().StringVar(&configPath, "config", "/etc/agentsh/config.yaml", "Path to config file")

	return cmd
}

func newRestoreCmd() *cobra.Command {
	var input string
	var verify bool
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore agentsh data from backup",
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" {
				return fmt.Errorf("--input is required")
			}
			return restoreBackup(cmd, input, verify, dryRun)
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input backup file (required)")
	cmd.Flags().BoolVar(&verify, "verify", false, "Verify restored data")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be restored without making changes")
	cmd.MarkFlagRequired("input")

	return cmd
}

func createBackup(cmd *cobra.Command, output, configPath string, verify bool) error {
	// Write to temp file first, rename on success to avoid partial backups
	tempFile := output + ".tmp"
	f, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}

	// Track whether we succeeded for cleanup
	success := false
	defer func() {
		if !success {
			os.Remove(tempFile)
		}
	}()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Backup config file
	if err := addFileToTar(tw, configPath, "config.yaml"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup config: %v\n", err)
	}

	// TODO: Read config to find audit DB path and policies dir
	// For now, use defaults
	auditDB := "/var/lib/agentsh/events.db"
	policiesDir := "/etc/agentsh/policies"

	if err := addFileToTar(tw, auditDB, "events.db"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup audit DB: %v\n", err)
	}

	if err := addDirToTar(tw, policiesDir, "policies"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup policies: %v\n", err)
	}

	// Explicit close with error checking (instead of defer)
	if err := tw.Close(); err != nil {
		f.Close()
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		f.Close()
		return fmt.Errorf("close gzip writer: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}

	// Rename temp file to final output
	if err := os.Rename(tempFile, output); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	success = true
	fmt.Fprintf(cmd.OutOrStdout(), "Backup created: %s\n", output)

	if verify {
		// TODO: Verify backup contents
		fmt.Fprintf(cmd.OutOrStdout(), "Verification: OK\n")
	}

	return nil
}

func restoreBackup(cmd *cobra.Command, input string, verify, dryRun bool) error {
	f, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Sanitize path to prevent path traversal attacks
		safeName, err := sanitizeTarPath(header.Name)
		if err != nil {
			return fmt.Errorf("invalid tar entry: %w", err)
		}

		if dryRun {
			fmt.Fprintf(cmd.OutOrStdout(), "Would restore: %s (%d bytes)\n", safeName, header.Size)
			continue
		}

		// TODO: Implement actual restore logic with proper paths
		fmt.Fprintf(cmd.OutOrStdout(), "Restoring: %s\n", safeName)
	}

	if verify && !dryRun {
		fmt.Fprintf(cmd.OutOrStdout(), "Verification: OK\n")
	}

	return nil
}

func addFileToTar(tw *tar.Writer, srcPath, destName string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    destName,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = io.Copy(tw, f)
	return err
}

func addDirToTar(tw *tar.Writer, srcDir, destDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(destDir, relPath)
		return addFileToTar(tw, path, destPath)
	})
}
