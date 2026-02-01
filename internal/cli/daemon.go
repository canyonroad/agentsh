package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// PNACLSession represents session context for the PNACL daemon.
type PNACLSession struct {
	ID           string    `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	ComputerName string    `json:"computer_name"` // hostname
	ComputerIP   []string  `json:"computer_ip"`   // all active interface IPs
	Username     string    `json:"username"`      // logged-in user
	UserID       string    `json:"user_id"`       // UID
	Status       string    `json:"status"`        // running, paused, stopped
	EventCount   int64     `json:"event_count"`   // connections tracked
	Version      string    `json:"version"`       // agentsh version
	Platform     string    `json:"platform"`      // OS platform
}

func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the agentsh daemon",
		Long: `Manage the agentsh daemon for background network monitoring.

The daemon runs as a systemd user service on Linux, providing persistent
network monitoring and policy enforcement. On macOS, it uses launchd.`,
	}

	cmd.AddCommand(newDaemonInstallCmd())
	cmd.AddCommand(newDaemonUninstallCmd())
	cmd.AddCommand(newDaemonStatusCmd())
	cmd.AddCommand(newDaemonRestartCmd())

	return cmd
}

func newDaemonInstallCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install startup integration for current OS",
		Long: `Install the agentsh daemon as a system service.

On Linux, this creates a systemd user service at ~/.config/systemd/user/agentsh.service
that starts automatically on user login.

On macOS, this creates a launchd plist at ~/Library/LaunchAgents/com.agentsh.daemon.plist.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()

			switch runtime.GOOS {
			case "linux":
				return installSystemdService(cmd, force)
			case "darwin":
				return installLaunchdService(cmd, force)
			default:
				fmt.Fprintf(w, "Daemon installation not supported on %s\n", runtime.GOOS)
				fmt.Fprintln(w, "Run 'agentsh server' manually instead")
				return nil
			}
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing service file")

	return cmd
}

func newDaemonUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove startup integration",
		Long: `Remove the agentsh daemon system service.

This stops the running daemon and removes the service configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch runtime.GOOS {
			case "linux":
				return uninstallSystemdService(cmd)
			case "darwin":
				return uninstallLaunchdService(cmd)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "Daemon uninstall not supported on %s\n", runtime.GOOS)
				return nil
			}
		},
	}

	return cmd
}

func newDaemonStatusCmd() *cobra.Command {
	var outputJSON bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current session info",
		Long: `Show the current daemon session information.

Displays the session name, computer IP, username, uptime, and event statistics.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			session, err := getCurrentSession(cmd)
			if err != nil {
				if outputJSON {
					return printJSON(cmd, map[string]any{
						"status": "stopped",
						"error":  err.Error(),
					})
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Daemon status: stopped\n")
				fmt.Fprintf(cmd.OutOrStdout(), "Error: %v\n", err)
				return nil
			}

			if outputJSON {
				return printJSON(cmd, session)
			}

			// Human-readable output
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Daemon status: %s\n", session.Status)
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Session ID:    %s\n", session.ID)
			fmt.Fprintf(w, "Started:       %s\n", session.StartedAt.Format(time.RFC3339))
			fmt.Fprintf(w, "Uptime:        %s\n", formatUptime(time.Since(session.StartedAt)))
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Computer:      %s\n", session.ComputerName)
			fmt.Fprintf(w, "IP Addresses:  %s\n", strings.Join(session.ComputerIP, ", "))
			fmt.Fprintf(w, "Username:      %s (uid: %s)\n", session.Username, session.UserID)
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Events tracked: %d\n", session.EventCount)
			fmt.Fprintf(w, "Version:       %s\n", session.Version)
			fmt.Fprintf(w, "Platform:      %s\n", session.Platform)

			return nil
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

func newDaemonRestartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart monitoring with fresh session",
		Long: `Restart the daemon with a fresh monitoring session.

This stops the current daemon, clears session state, and starts a new session.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()

			switch runtime.GOOS {
			case "linux":
				fmt.Fprintln(w, "Restarting agentsh daemon...")
				if err := runSystemctl("restart", "agentsh"); err != nil {
					return fmt.Errorf("restart failed: %w", err)
				}
				fmt.Fprintln(w, "Daemon restarted successfully")
				return nil

			case "darwin":
				fmt.Fprintln(w, "Restarting agentsh daemon...")
				// Unload and reload the service
				plistPath := getLaunchdPlistPath()
				_ = exec.Command("launchctl", "unload", plistPath).Run()
				if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
					return fmt.Errorf("restart failed: %w", err)
				}
				fmt.Fprintln(w, "Daemon restarted successfully")
				return nil

			default:
				fmt.Fprintf(w, "Daemon restart not supported on %s\n", runtime.GOOS)
				return nil
			}
		},
	}

	return cmd
}

// systemd service generation

const systemdServiceTemplate = `[Unit]
Description=agentsh daemon - Agent shell security monitoring
Documentation=https://github.com/agentsh/agentsh
After=network.target

[Service]
Type=simple
ExecStart=%s server --daemon
Restart=on-failure
RestartSec=5
Environment=HOME=%s
Environment=XDG_RUNTIME_DIR=/run/user/%s

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=%s

[Install]
WantedBy=default.target
`

func installSystemdService(cmd *cobra.Command, force bool) error {
	w := cmd.OutOrStdout()

	// Get user info
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	// Get agentsh binary path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// Ensure systemd user directory exists
	systemdDir := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return fmt.Errorf("create systemd directory: %w", err)
	}

	servicePath := filepath.Join(systemdDir, "agentsh.service")

	// Check if service already exists
	if _, err := os.Stat(servicePath); err == nil && !force {
		fmt.Fprintf(w, "Service file already exists at %s\n", servicePath)
		fmt.Fprintln(w, "Use --force to overwrite")
		return nil
	}

	// Data directory for read-write access
	dataDir := filepath.Join(currentUser.HomeDir, ".local", "share", "agentsh")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	// Generate service content
	serviceContent := fmt.Sprintf(systemdServiceTemplate,
		exePath,
		currentUser.HomeDir,
		currentUser.Uid,
		dataDir,
	)

	// Write service file
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	fmt.Fprintf(w, "Service installed: %s\n", servicePath)
	fmt.Fprintln(w)

	// Reload systemd
	if err := runSystemctl("daemon-reload", ""); err != nil {
		fmt.Fprintf(w, "Warning: failed to reload systemd: %v\n", err)
	}

	// Enable service
	if err := runSystemctl("enable", "agentsh"); err != nil {
		fmt.Fprintf(w, "Warning: failed to enable service: %v\n", err)
	} else {
		fmt.Fprintln(w, "Service enabled for automatic start on login")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "To start the daemon now:")
	fmt.Fprintln(w, "  systemctl --user start agentsh")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To check status:")
	fmt.Fprintln(w, "  systemctl --user status agentsh")
	fmt.Fprintln(w, "  agentsh daemon status")

	return nil
}

func uninstallSystemdService(cmd *cobra.Command) error {
	w := cmd.OutOrStdout()

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	servicePath := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", "agentsh.service")

	// Stop service if running
	_ = runSystemctl("stop", "agentsh")

	// Disable service
	_ = runSystemctl("disable", "agentsh")

	// Remove service file
	if err := os.Remove(servicePath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(w, "Service file not found, nothing to uninstall")
			return nil
		}
		return fmt.Errorf("remove service file: %w", err)
	}

	// Reload systemd
	_ = runSystemctl("daemon-reload", "")

	fmt.Fprintln(w, "Service uninstalled successfully")
	return nil
}

func runSystemctl(action, service string) error {
	var args []string
	args = append(args, "--user")
	args = append(args, action)
	if service != "" {
		args = append(args, service)
	}

	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// launchd service generation (macOS)

const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.agentsh.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>server</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>%s/agentsh.log</string>
    <key>StandardErrorPath</key>
    <string>%s/agentsh.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>%s</string>
    </dict>
</dict>
</plist>
`

func getLaunchdPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", "com.agentsh.daemon.plist")
}

func installLaunchdService(cmd *cobra.Command, force bool) error {
	w := cmd.OutOrStdout()

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// Ensure LaunchAgents directory exists
	launchAgentsDir := filepath.Join(currentUser.HomeDir, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentsDir, 0755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}

	plistPath := getLaunchdPlistPath()

	if _, err := os.Stat(plistPath); err == nil && !force {
		fmt.Fprintf(w, "Plist file already exists at %s\n", plistPath)
		fmt.Fprintln(w, "Use --force to overwrite")
		return nil
	}

	// Log directory
	logDir := filepath.Join(currentUser.HomeDir, "Library", "Logs", "agentsh")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	plistContent := fmt.Sprintf(launchdPlistTemplate,
		exePath,
		logDir,
		logDir,
		currentUser.HomeDir,
	)

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("write plist file: %w", err)
	}

	fmt.Fprintf(w, "Service installed: %s\n", plistPath)
	fmt.Fprintln(w)

	// Load the service
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		fmt.Fprintf(w, "Warning: failed to load service: %v\n", err)
	} else {
		fmt.Fprintln(w, "Service loaded and started")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "To check status:")
	fmt.Fprintln(w, "  launchctl list | grep agentsh")
	fmt.Fprintln(w, "  agentsh daemon status")

	return nil
}

func uninstallLaunchdService(cmd *cobra.Command) error {
	w := cmd.OutOrStdout()

	plistPath := getLaunchdPlistPath()

	// Unload service if loaded
	_ = exec.Command("launchctl", "unload", plistPath).Run()

	// Remove plist file
	if err := os.Remove(plistPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(w, "Plist file not found, nothing to uninstall")
			return nil
		}
		return fmt.Errorf("remove plist file: %w", err)
	}

	fmt.Fprintln(w, "Service uninstalled successfully")
	return nil
}

// Session context capture

func getCurrentSession(cmd *cobra.Command) (*PNACLSession, error) {
	cfg := getClientConfig(cmd)

	// Try to get session from running daemon
	// For now, we'll construct session info from local system info
	// In production, this would query the running daemon

	session := &PNACLSession{
		ID:        generateSessionID(),
		StartedAt: time.Now(), // Would come from daemon
		Status:    "unknown",
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err == nil {
		session.ComputerName = hostname
	}

	// Get all active interface IPs
	session.ComputerIP = getActiveIPs()

	// Get current user
	currentUser, err := user.Current()
	if err == nil {
		session.Username = currentUser.Username
		session.UserID = currentUser.Uid
	}

	// Check if daemon is running
	switch runtime.GOOS {
	case "linux":
		output, err := exec.Command("systemctl", "--user", "is-active", "agentsh").Output()
		if err == nil {
			status := strings.TrimSpace(string(output))
			if status == "active" {
				session.Status = "running"
			} else {
				session.Status = status
			}
		} else {
			session.Status = "stopped"
		}
	case "darwin":
		output, err := exec.Command("launchctl", "list").Output()
		if err == nil && strings.Contains(string(output), "com.agentsh.daemon") {
			session.Status = "running"
		} else {
			session.Status = "stopped"
		}
	default:
		// Try HTTP health check
		session.Status = "unknown"
	}

	// Try to get more info from the running daemon via API
	if session.Status == "running" {
		// In production, query the daemon's /api/v1/status endpoint
		_ = cfg // Would use this to make API call
	}

	return session, nil
}

func getActiveIPs() []string {
	var ips []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip loopback and link-local addresses
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			ips = append(ips, ip.String())
		}
	}

	return ips
}

func generateSessionID() string {
	hostname, _ := os.Hostname()
	timestamp := time.Now().UnixNano()
	// Add random suffix to ensure uniqueness even for rapid consecutive calls
	randomBytes := make([]byte, 4)
	_, _ = rand.Read(randomBytes)
	randomSuffix := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("%s-%d-%s", hostname, timestamp, randomSuffix)
}

func formatUptime(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}
