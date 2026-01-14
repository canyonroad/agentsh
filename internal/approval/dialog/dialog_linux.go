//go:build linux

package dialog

import (
	"context"
	"os/exec"
	"strings"
)

// hasDialogBackend returns true if zenity or kdialog is available.
func hasDialogBackend() bool {
	// Check for zenity
	if _, err := exec.LookPath("zenity"); err == nil {
		return true
	}
	// Check for kdialog
	if _, err := exec.LookPath("kdialog"); err == nil {
		return true
	}
	// WSL can use PowerShell
	if IsWSL() {
		if _, err := exec.LookPath("powershell.exe"); err == nil {
			return true
		}
	}
	return false
}

// showNative shows a dialog using zenity, kdialog, or PowerShell (WSL).
func showNative(ctx context.Context, req Request) (Response, error) {
	// Try zenity first
	if path, err := exec.LookPath("zenity"); err == nil {
		return showZenity(ctx, path, req)
	}

	// Try kdialog
	if path, err := exec.LookPath("kdialog"); err == nil {
		return showKDialog(ctx, path, req)
	}

	// WSL fallback to PowerShell
	if IsWSL() {
		if path, err := exec.LookPath("powershell.exe"); err == nil {
			return showPowerShell(ctx, path, req)
		}
	}

	return Response{}, ErrNoBackend
}

// showZenity shows a dialog using zenity.
func showZenity(ctx context.Context, path string, req Request) (Response, error) {
	args := []string{
		"--question",
		"--title=" + req.Title,
		"--text=" + req.Message,
		"--ok-label=" + req.AllowLabel,
		"--cancel-label=" + req.DenyLabel,
	}

	cmd := exec.CommandContext(ctx, path, args...)
	err := cmd.Run()

	if ctx.Err() != nil {
		return Response{TimedOut: true}, ctx.Err()
	}

	// Exit code 0 = OK (Allow), 1 = Cancel (Deny), 5 = Timeout
	if err == nil {
		return Response{Allowed: true}, nil
	}

	// Any error (including exit code 1) means Deny
	return Response{Allowed: false}, nil
}

// showKDialog shows a dialog using kdialog.
func showKDialog(ctx context.Context, path string, req Request) (Response, error) {
	args := []string{
		"--title", req.Title,
		"--yesno", req.Message,
		"--yes-label", req.AllowLabel,
		"--no-label", req.DenyLabel,
	}

	cmd := exec.CommandContext(ctx, path, args...)
	err := cmd.Run()

	if ctx.Err() != nil {
		return Response{TimedOut: true}, ctx.Err()
	}

	// Exit code 0 = Yes (Allow), non-zero = No (Deny)
	if err == nil {
		return Response{Allowed: true}, nil
	}

	return Response{Allowed: false}, nil
}

// showPowerShell shows a dialog using PowerShell (for WSL).
func showPowerShell(ctx context.Context, path string, req Request) (Response, error) {
	// Escape special characters for PowerShell to prevent command injection
	message := escapePowerShell(req.Message)
	title := escapePowerShell(req.Title)

	script := `Add-Type -AssemblyName System.Windows.Forms; ` +
		`[System.Windows.Forms.MessageBox]::Show("` + message + `", "` + title + `", "YesNo", "Question")`

	cmd := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()

	if ctx.Err() != nil {
		return Response{TimedOut: true}, ctx.Err()
	}

	if err != nil {
		return Response{}, err
	}

	// "Yes" = Allow, "No" = Deny
	result := strings.TrimSpace(string(output))
	return Response{Allowed: result == "Yes"}, nil
}

// escapePowerShell escapes special characters for PowerShell strings.
// This prevents command injection via $variable or $(subexpression) syntax.
func escapePowerShell(s string) string {
	// Escape backticks first (they're the escape character in PowerShell)
	s = strings.ReplaceAll(s, "`", "``")
	// Escape dollar signs to prevent variable/subexpression expansion
	s = strings.ReplaceAll(s, "$", "`$")
	// Escape double quotes
	s = strings.ReplaceAll(s, `"`, "`\"")
	// Convert newlines to PowerShell newline
	s = strings.ReplaceAll(s, "\n", "`n")
	return s
}
