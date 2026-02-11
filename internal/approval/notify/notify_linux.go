//go:build linux

package notify

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// hasNotifyBackend returns true if notify-send with --action support is available.
func hasNotifyBackend() bool {
	path, err := exec.LookPath("notify-send")
	if err != nil {
		return false
	}

	// Verify --action flag support (libnotify >= 0.7.9)
	out, err := exec.Command(path, "--help").CombinedOutput()
	if err != nil {
		return false
	}

	return strings.Contains(string(out), "--action")
}

// showNative shows a desktop notification with action buttons using notify-send.
func showNative(ctx context.Context, req Request) (Response, error) {
	path, err := exec.LookPath("notify-send")
	if err != nil {
		return Response{}, ErrNoBackend
	}

	args := []string{
		"--wait",
		fmt.Sprintf("--action=allow=%s", req.AllowLabel),
		fmt.Sprintf("--action=deny=%s", req.DenyLabel),
		fmt.Sprintf("--urgency=%s", req.Urgency),
	}

	if req.Timeout > 0 {
		args = append(args, fmt.Sprintf("--expire-time=%d", req.Timeout.Milliseconds()))
	}

	args = append(args, req.Title, req.Message)

	cmd := exec.CommandContext(ctx, path, args...)
	output, err := cmd.Output()

	if ctx.Err() != nil {
		return Response{TimedOut: true}, ctx.Err()
	}

	if err != nil {
		// notify-send exited with error — treat as dismissed
		return Response{Dismissed: true}, ErrDismissed
	}

	action := strings.TrimSpace(string(output))
	switch action {
	case "allow":
		return Response{Allowed: true}, nil
	case "deny":
		return Response{Allowed: false}, nil
	default:
		// Empty or unknown output — notification dismissed
		return Response{Dismissed: true}, ErrDismissed
	}
}
