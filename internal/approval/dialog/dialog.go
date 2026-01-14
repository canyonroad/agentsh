package dialog

import (
	"context"
	"errors"
	"time"
)

// ErrNoBackend is returned when no dialog backend is available.
var ErrNoBackend = errors.New("no dialog backend available")

// ErrTimeout is returned when the dialog times out.
var ErrTimeout = errors.New("dialog timed out")

// Request represents a dialog request.
type Request struct {
	// Title is the dialog window title.
	Title string

	// Message is the main dialog text.
	Message string

	// AllowLabel is the label for the allow/yes button (default: "Allow").
	AllowLabel string

	// DenyLabel is the label for the deny/no button (default: "Deny").
	DenyLabel string

	// Timeout is how long to wait for user response.
	// Zero means no timeout (wait indefinitely).
	Timeout time.Duration
}

// Response represents the user's dialog response.
type Response struct {
	// Allowed is true if user clicked the allow/yes button.
	Allowed bool

	// TimedOut is true if the dialog timed out without response.
	TimedOut bool
}

// Show displays a native dialog and returns the user's choice.
// Returns ErrNoBackend if no dialog backend is available.
// Returns ErrTimeout if the dialog times out (also sets Response.TimedOut).
func Show(ctx context.Context, req Request) (Response, error) {
	// Apply defaults
	if req.AllowLabel == "" {
		req.AllowLabel = "Allow"
	}
	if req.DenyLabel == "" {
		req.DenyLabel = "Deny"
	}

	// Check if we can show dialogs
	if !CanShowDialog() {
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
			return Response{TimedOut: true}, ErrTimeout
		}
		return resp, err
	}

	return resp, nil
}
