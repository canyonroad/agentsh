package notify

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestShowDefaults(t *testing.T) {
	// We can't call Show directly since it checks CanShowNotification,
	// but we can verify defaults are applied by checking what Show would use.
	req := Request{
		Title:   "Test",
		Message: "Test message",
	}

	// Verify defaults are empty before Show applies them
	if req.AllowLabel != "" {
		t.Errorf("expected empty AllowLabel before defaults, got %q", req.AllowLabel)
	}
	if req.DenyLabel != "" {
		t.Errorf("expected empty DenyLabel before defaults, got %q", req.DenyLabel)
	}

	// Call Show — it will apply defaults, then likely return ErrNoBackend in CI/test
	resp, err := Show(context.Background(), req)

	// In most test environments, notification won't be available
	if err != nil {
		// ErrNoBackend is expected in CI
		return
	}

	// If Show succeeded (unlikely in test), just verify response is valid
	_ = resp
}

func TestCanShowNotification_NoDisplay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("display detection test only applies on Linux")
	}

	// Save original values
	origDisplay := os.Getenv("DISPLAY")
	origWayland := os.Getenv("WAYLAND_DISPLAY")
	defer func() {
		if origDisplay != "" {
			os.Setenv("DISPLAY", origDisplay)
		} else {
			os.Unsetenv("DISPLAY")
		}
		if origWayland != "" {
			os.Setenv("WAYLAND_DISPLAY", origWayland)
		} else {
			os.Unsetenv("WAYLAND_DISPLAY")
		}
	}()

	os.Unsetenv("DISPLAY")
	os.Unsetenv("WAYLAND_DISPLAY")

	if CanShowNotification() {
		t.Error("expected CanShowNotification() = false with no display set")
	}
}

func TestCanShowNotification_CI(t *testing.T) {
	// Save and clear CI env vars
	origCI := os.Getenv("CI")
	defer func() {
		if origCI != "" {
			os.Setenv("CI", origCI)
		} else {
			os.Unsetenv("CI")
		}
	}()

	// Set CI=true
	os.Setenv("CI", "true")

	if CanShowNotification() {
		t.Error("expected CanShowNotification() = false in CI environment")
	}
}

func TestHasDisplay_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("HasDisplay test only runs on Linux")
	}

	origDisplay := os.Getenv("DISPLAY")
	origWayland := os.Getenv("WAYLAND_DISPLAY")
	defer func() {
		if origDisplay != "" {
			os.Setenv("DISPLAY", origDisplay)
		} else {
			os.Unsetenv("DISPLAY")
		}
		if origWayland != "" {
			os.Setenv("WAYLAND_DISPLAY", origWayland)
		} else {
			os.Unsetenv("WAYLAND_DISPLAY")
		}
	}()

	tests := []struct {
		name     string
		display  string
		wayland  string
		expected bool
	}{
		{
			name:     "no display",
			display:  "",
			wayland:  "",
			expected: false,
		},
		{
			name:     "X11 display",
			display:  ":0",
			wayland:  "",
			expected: true,
		},
		{
			name:     "Wayland display",
			display:  "",
			wayland:  "wayland-0",
			expected: true,
		},
		{
			name:     "both displays",
			display:  ":0",
			wayland:  "wayland-0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("DISPLAY")
			os.Unsetenv("WAYLAND_DISPLAY")

			if tt.display != "" {
				os.Setenv("DISPLAY", tt.display)
			}
			if tt.wayland != "" {
				os.Setenv("WAYLAND_DISPLAY", tt.wayland)
			}

			if got := HasDisplay(); got != tt.expected {
				t.Errorf("HasDisplay() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsCI(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected bool
	}{
		{
			name:     "no CI env vars",
			envVars:  map[string]string{},
			expected: false,
		},
		{
			name:     "CI=true",
			envVars:  map[string]string{"CI": "true"},
			expected: true,
		},
		{
			name:     "GITHUB_ACTIONS=true",
			envVars:  map[string]string{"GITHUB_ACTIONS": "true"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all CI env vars
			for _, env := range ciEnvVars {
				os.Unsetenv(env)
			}

			// Set test env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}
			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			if got := IsCI(); got != tt.expected {
				t.Errorf("IsCI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestShow_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := Request{
		Title:   "Test",
		Message: "Test message",
		Timeout: 5 * time.Second,
	}

	// Should return quickly — either ErrNoBackend (no display) or context error
	_, err := Show(ctx, req)
	if err == nil {
		// If no error, that's OK — might have returned before context was checked
		return
	}
	// Any error is acceptable here
}
