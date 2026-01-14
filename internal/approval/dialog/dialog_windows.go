//go:build windows

package dialog

import (
	"context"
	"os/exec"
	"strings"
)

// hasDialogBackend returns true - Windows always has PowerShell.
func hasDialogBackend() bool {
	_, err := exec.LookPath("powershell.exe")
	return err == nil
}

// showNative shows a dialog using PowerShell MessageBox.
func showNative(ctx context.Context, req Request) (Response, error) {
	path, err := exec.LookPath("powershell.exe")
	if err != nil {
		return Response{}, ErrNoBackend
	}

	// Escape special characters for PowerShell
	message := escapePowerShell(req.Message)
	title := escapePowerShell(req.Title)

	// Build PowerShell command
	// Using YesNo buttons where Yes = Allow, No = Deny
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
