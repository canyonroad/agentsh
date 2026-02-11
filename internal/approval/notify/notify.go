package notify

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"
)

// ErrNoBackend is returned when no notification backend is available.
var ErrNoBackend = errors.New("no notification backend available")

// ErrDismissed is returned when the notification is dismissed without action.
var ErrDismissed = errors.New("notification dismissed")

// Request represents a desktop notification request with action buttons.
type Request struct {
	// Title is the notification title.
	Title string

	// Message is the notification body text.
	Message string

	// AllowLabel is the label for the allow action button (default: "Allow").
	AllowLabel string

	// DenyLabel is the label for the deny action button (default: "Deny").
	DenyLabel string

	// Timeout is how long to wait for user response.
	// Zero means no timeout (wait indefinitely).
	Timeout time.Duration

	// Urgency is the notification urgency level: "low", "normal", or "critical".
	// Empty defaults to "normal".
	Urgency string
}

// Response represents the user's notification action response.
type Response struct {
	// Allowed is true if user clicked the allow action button.
	Allowed bool

	// Dismissed is true if the notification was dismissed without clicking an action.
	Dismissed bool

	// TimedOut is true if the notification timed out without response.
	TimedOut bool
}

// ciEnvVars is a list of environment variables that indicate CI environment.
var ciEnvVars = []string{
	"CI",
	"GITHUB_ACTIONS",
	"GITLAB_CI",
	"CIRCLECI",
	"TRAVIS",
	"JENKINS_URL",
	"BUILDKITE",
	"TEAMCITY_VERSION",
	"TF_BUILD",
}

// Show displays a desktop notification with action buttons and returns the user's choice.
// Returns ErrNoBackend if no notification backend is available.
// Returns ErrDismissed if the notification is dismissed without action.
func Show(ctx context.Context, req Request) (Response, error) {
	// Apply defaults
	if req.AllowLabel == "" {
		req.AllowLabel = "Allow"
	}
	if req.DenyLabel == "" {
		req.DenyLabel = "Deny"
	}
	if req.Urgency == "" {
		req.Urgency = "normal"
	}

	// Check if we can show notifications
	if !CanShowNotification() {
		return Response{}, ErrNoBackend
	}

	// Create timeout context if needed
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	// Call platform-specific implementation
	resp, err := showNative(ctx, req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Response{TimedOut: true}, ctx.Err()
		}
		return resp, err
	}

	return resp, nil
}

// CanShowNotification returns true if a notification backend is available on this platform.
func CanShowNotification() bool {
	if !HasDisplay() {
		return false
	}
	if IsCI() {
		return false
	}
	return hasNotifyBackend()
}

// HasDisplay returns true if a display is available for showing notifications.
func HasDisplay() bool {
	switch runtime.GOOS {
	case "linux":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	case "darwin", "windows":
		return true
	default:
		return false
	}
}

// IsCI returns true if running in a CI environment.
func IsCI() bool {
	for _, env := range ciEnvVars {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}
