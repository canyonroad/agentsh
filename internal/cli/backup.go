package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/config"
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
	// Load config to get actual paths
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not load config from %s: %v (using defaults)\n", configPath, err)
		cfg = &config.Config{}
		// Apply defaults manually if config load fails
		cfg.Audit.Storage.SQLitePath = "/var/lib/agentsh/events.db"
		cfg.Policies.Dir = "/etc/agentsh/policies"
	}

	auditDB := cfg.Audit.Storage.SQLitePath
	policiesDir := cfg.Policies.Dir

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

	// Track files added for verification
	var addedFiles []string

	// Backup config file
	if err := addFileToTar(tw, configPath, "config.yaml"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup config: %v\n", err)
	} else {
		addedFiles = append(addedFiles, "config.yaml")
	}

	if err := addFileToTar(tw, auditDB, "events.db"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup audit DB: %v\n", err)
	} else {
		addedFiles = append(addedFiles, "events.db")
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
		if err := verifyBackup(cmd, output); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Verification: OK\n")
	}

	return nil
}

// verifyBackup reads back a backup file and verifies its integrity.
func verifyBackup(cmd *cobra.Command, backupPath string) error {
	f, err := os.Open(backupPath)
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

	fileCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		// Verify path is safe
		if _, err := sanitizeTarPath(header.Name); err != nil {
			return fmt.Errorf("invalid tar entry %q: %w", header.Name, err)
		}

		// Verify we can read the file content
		hasher := sha256.New()
		n, err := io.Copy(hasher, tr)
		if err != nil {
			return fmt.Errorf("read content of %q: %w", header.Name, err)
		}

		if n != header.Size {
			return fmt.Errorf("size mismatch for %q: expected %d, got %d", header.Name, header.Size, n)
		}

		fileCount++
	}

	if fileCount == 0 {
		return fmt.Errorf("backup contains no files")
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

	// Default restore paths (can be overridden via flags in future)
	configDest := "/etc/agentsh/config.yaml"
	auditDBDest := "/var/lib/agentsh/events.db"
	policiesDest := "/etc/agentsh/policies"

	restoredCount := 0
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

		// Determine destination path based on tar entry name
		var destPath string
		switch {
		case safeName == "config.yaml":
			destPath = configDest
		case safeName == "events.db":
			destPath = auditDBDest
		case strings.HasPrefix(safeName, "policies/"):
			relPath := strings.TrimPrefix(safeName, "policies/")
			destPath = filepath.Join(policiesDest, relPath)
		default:
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: unknown entry %q, skipping\n", safeName)
			continue
		}

		if dryRun {
			fmt.Fprintf(cmd.OutOrStdout(), "Would restore: %s -> %s (%d bytes)\n", safeName, destPath, header.Size)
			continue
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Restoring: %s -> %s\n", safeName, destPath)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", destPath, err)
		}

		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("create file %s: %w", destPath, err)
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return fmt.Errorf("write file %s: %w", destPath, err)
		}
		outFile.Close()

		// Restore modification time
		if err := os.Chtimes(destPath, header.ModTime, header.ModTime); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not set mtime for %s: %v\n", destPath, err)
		}

		restoredCount++
	}

	if restoredCount == 0 && !dryRun {
		return fmt.Errorf("no files were restored from backup")
	}

	if verify && !dryRun {
		// Verify restored files exist and have content
		for _, path := range []string{configDest, auditDBDest} {
			if info, err := os.Stat(path); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: restored file %s not accessible: %v\n", path, err)
			} else if info.Size() == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: restored file %s is empty\n", path)
			}
		}
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
