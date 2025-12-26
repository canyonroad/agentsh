package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// DiagnosticCollector collects diagnostic information.
type DiagnosticCollector struct {
	client       Client
	output       io.Writer
	redactSecrets bool
}

// DiagnosticConfig configures the collector.
type DiagnosticConfig struct {
	Client        Client
	Output        io.Writer
	RedactSecrets bool
}

// NewDiagnosticCollector creates a new diagnostic collector.
func NewDiagnosticCollector(config DiagnosticConfig) *DiagnosticCollector {
	redact := config.RedactSecrets
	if !redact {
		redact = true // Default to redacting secrets
	}
	return &DiagnosticCollector{
		client:        config.Client,
		output:        config.Output,
		redactSecrets: redact,
	}
}

// DiagnosticReport contains all diagnostic information.
type DiagnosticReport struct {
	GeneratedAt   time.Time         `json:"generated_at"`
	Version       string            `json:"version"`
	SystemInfo    SystemInfo        `json:"system_info"`
	Status        *Status           `json:"status,omitempty"`
	Metrics       *Metrics          `json:"metrics,omitempty"`
	Config        map[string]any    `json:"config,omitempty"`
	Sessions      []SessionInfo     `json:"sessions,omitempty"`
	RecentEvents  []Event           `json:"recent_events,omitempty"`
	Errors        []string          `json:"errors,omitempty"`
}

// SystemInfo contains system information.
type SystemInfo struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	NumCPU       int    `json:"num_cpu"`
	GoVersion    string `json:"go_version"`
	Hostname     string `json:"hostname,omitempty"`
	WorkingDir   string `json:"working_dir,omitempty"`
}

// Collect gathers diagnostic information.
func (d *DiagnosticCollector) Collect(ctx context.Context) (*DiagnosticReport, error) {
	report := &DiagnosticReport{
		GeneratedAt: time.Now(),
		Version:     "1.0.0",
		Errors:      []string{},
	}

	// Collect system info
	report.SystemInfo = d.collectSystemInfo()

	// Collect status
	if status, err := d.client.GetStatus(ctx); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("status: %v", err))
	} else {
		report.Status = status
	}

	// Collect metrics
	if metrics, err := d.client.GetMetrics(ctx); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("metrics: %v", err))
	} else {
		report.Metrics = metrics
	}

	// Collect config
	if config, err := d.client.GetConfig(ctx, true); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("config: %v", err))
	} else {
		if d.redactSecrets {
			config = d.redactConfig(config)
		}
		report.Config = config
	}

	// Collect sessions
	if sessions, err := d.client.ListSessions(ctx, ListSessionsOpts{}); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("sessions: %v", err))
	} else {
		report.Sessions = sessions
	}

	return report, nil
}

func (d *DiagnosticCollector) collectSystemInfo() SystemInfo {
	info := SystemInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
		GoVersion: runtime.Version(),
	}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	if wd, err := os.Getwd(); err == nil {
		info.WorkingDir = wd
	}

	return info
}

func (d *DiagnosticCollector) redactConfig(config map[string]any) map[string]any {
	sensitivePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)password`),
		regexp.MustCompile(`(?i)secret`),
		regexp.MustCompile(`(?i)token`),
		regexp.MustCompile(`(?i)key`),
		regexp.MustCompile(`(?i)credential`),
		regexp.MustCompile(`(?i)auth`),
	}

	return d.redactMap(config, sensitivePatterns)
}

func (d *DiagnosticCollector) redactMap(m map[string]any, patterns []*regexp.Regexp) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		isSensitive := false
		for _, p := range patterns {
			if p.MatchString(k) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			result[k] = "[REDACTED]"
		} else if nested, ok := v.(map[string]any); ok {
			result[k] = d.redactMap(nested, patterns)
		} else {
			result[k] = v
		}
	}
	return result
}

// WriteReport writes the report to a file.
func (d *DiagnosticCollector) WriteReport(report *DiagnosticReport, outputPath string) error {
	// Determine format from extension
	ext := strings.ToLower(filepath.Ext(outputPath))

	switch ext {
	case ".json":
		return d.writeJSON(report, outputPath)
	case ".gz", ".tar.gz", ".tgz":
		return d.writeTarGz(report, outputPath)
	default:
		return d.writeJSON(report, outputPath)
	}
}

func (d *DiagnosticCollector) writeJSON(report *DiagnosticReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (d *DiagnosticCollector) writeTarGz(report *DiagnosticReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add report.json
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}

	if err := d.addToTar(tw, "report.json", reportData); err != nil {
		return err
	}

	// Add system_info.json
	sysData, _ := json.MarshalIndent(report.SystemInfo, "", "  ")
	if err := d.addToTar(tw, "system_info.json", sysData); err != nil {
		return err
	}

	// Add metrics.json if available
	if report.Metrics != nil {
		metricsData, _ := json.MarshalIndent(report.Metrics, "", "  ")
		if err := d.addToTar(tw, "metrics.json", metricsData); err != nil {
			return err
		}
	}

	// Add config.json if available
	if report.Config != nil {
		configData, _ := json.MarshalIndent(report.Config, "", "  ")
		if err := d.addToTar(tw, "config.json", configData); err != nil {
			return err
		}
	}

	// Add sessions.json if available
	if len(report.Sessions) > 0 {
		sessionsData, _ := json.MarshalIndent(report.Sessions, "", "  ")
		if err := d.addToTar(tw, "sessions.json", sessionsData); err != nil {
			return err
		}
	}

	return nil
}

func (d *DiagnosticCollector) addToTar(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("writing tar header for %s: %w", name, err)
	}

	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("writing tar content for %s: %w", name, err)
	}

	return nil
}

// GenerateReport collects diagnostics and writes to a file.
func (d *DiagnosticCollector) GenerateReport(ctx context.Context, outputPath string) error {
	fmt.Fprintln(d.output, "Collecting diagnostic information...")

	report, err := d.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collecting diagnostics: %w", err)
	}

	steps := []string{
		"System information",
		"agentsh configuration (secrets redacted)",
		"Active policies",
		"Metrics snapshot",
		"Active sessions summary",
	}

	for _, step := range steps {
		fmt.Fprintf(d.output, "  ✓ %s\n", step)
	}

	if err := d.WriteReport(report, outputPath); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	// Get file size
	info, err := os.Stat(outputPath)
	size := "unknown"
	if err == nil {
		size = formatSize(info.Size())
	}

	fmt.Fprintln(d.output, "")
	fmt.Fprintf(d.output, "Report saved to: %s\n", outputPath)
	fmt.Fprintf(d.output, "Size: %s\n", size)
	fmt.Fprintln(d.output, "")
	fmt.Fprintln(d.output, "WARNING: Review report before sharing. May contain sensitive paths.")

	return nil
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
