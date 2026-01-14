//go:build darwin

package dialog

import (
	"context"
	"os/exec"
	"strings"
)

// hasDialogBackend returns true - macOS always has osascript.
func hasDialogBackend() bool {
	_, err := exec.LookPath("osascript")
	return err == nil
}

// showNative shows a dialog using osascript (AppleScript).
func showNative(ctx context.Context, req Request) (Response, error) {
	path, err := exec.LookPath("osascript")
	if err != nil {
		return Response{}, ErrNoBackend
	}

	// Escape special characters for AppleScript
	message := escapeAppleScript(req.Message)
	title := escapeAppleScript(req.Title)
	allowLabel := escapeAppleScript(req.AllowLabel)
	denyLabel := escapeAppleScript(req.DenyLabel)

	// Build AppleScript command
	// Note: buttons are listed right-to-left, so Deny comes first to appear on the left
	script := `display dialog "` + message + `" ` +
		`with title "` + title + `" ` +
		`buttons {"` + denyLabel + `", "` + allowLabel + `"} ` +
		`default button "` + denyLabel + `"`

	cmd := exec.CommandContext(ctx, path, "-e", script)
	output, err := cmd.Output()

	if ctx.Err() != nil {
		return Response{TimedOut: true}, ctx.Err()
	}

	if err != nil {
		// User clicked Cancel/Deny or closed the dialog
		return Response{Allowed: false}, nil
	}

	// Parse output: "button returned:Allow"
	result := string(output)
	if strings.Contains(result, "button returned:"+req.AllowLabel) {
		return Response{Allowed: true}, nil
	}

	return Response{Allowed: false}, nil
}

// escapeAppleScript escapes special characters for AppleScript strings.
func escapeAppleScript(s string) string {
	// Escape backslashes first, then double quotes
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// Convert newlines to AppleScript line breaks
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
