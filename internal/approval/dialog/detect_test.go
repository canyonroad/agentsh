package dialog

import (
	"os"
	"runtime"
	"testing"
)

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
		{
			name:     "GITLAB_CI=true",
			envVars:  map[string]string{"GITLAB_CI": "true"},
			expected: true,
		},
		{
			name:     "JENKINS_URL set",
			envVars:  map[string]string{"JENKINS_URL": "http://jenkins.example.com"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all CI env vars first
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

func TestHasDisplay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("HasDisplay test only runs on Linux")
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

func TestIsEnabled(t *testing.T) {
	// Clear CI env vars for predictable testing
	for _, env := range ciEnvVars {
		os.Unsetenv(env)
	}

	tests := []struct {
		name     string
		mode     string
		setupEnv func()
		cleanup  func()
		expected bool
	}{
		{
			name:     "disabled mode",
			mode:     "disabled",
			expected: false,
		},
		{
			name:     "enabled mode",
			mode:     "enabled",
			expected: true,
		},
		{
			name:     "auto mode in CI",
			mode:     "auto",
			setupEnv: func() { os.Setenv("CI", "true") },
			cleanup:  func() { os.Unsetenv("CI") },
			expected: false,
		},
		{
			name:     "empty mode (defaults to auto) in CI",
			mode:     "",
			setupEnv: func() { os.Setenv("CI", "true") },
			cleanup:  func() { os.Unsetenv("CI") },
			expected: false,
		},
		{
			name:     "unknown mode treated as auto in CI",
			mode:     "unknown",
			setupEnv: func() { os.Setenv("CI", "true") },
			cleanup:  func() { os.Unsetenv("CI") },
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				tt.setupEnv()
			}
			if tt.cleanup != nil {
				defer tt.cleanup()
			}

			if got := IsEnabled(tt.mode); got != tt.expected {
				t.Errorf("IsEnabled(%q) = %v, want %v", tt.mode, got, tt.expected)
			}
		})
	}
}
