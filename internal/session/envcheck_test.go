package session

import (
	"runtime"
	"strings"
	"testing"
)

func TestCheckEnvCollisions_NoCollision(t *testing.T) {
	serviceEnv := map[string]string{"GITHUB_TOKEN": "fake_gh"}
	envInject := map[string]string{"MY_VAR": "value"}
	if err := CheckEnvCollisions(serviceEnv, envInject); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckEnvCollisions_Collision(t *testing.T) {
	serviceEnv := map[string]string{"GITHUB_TOKEN": "fake_gh"}
	envInject := map[string]string{"GITHUB_TOKEN": "other_value"}
	err := CheckEnvCollisions(serviceEnv, envInject)
	if err == nil {
		t.Fatal("expected error for collision")
	}
	if !strings.HasPrefix(err.Error(), "env_inject_service_collision:") {
		t.Errorf("expected env_inject_service_collision prefix, got: %v", err)
	}
}

func TestCheckEnvCollisions_BothNil(t *testing.T) {
	if err := CheckEnvCollisions(nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckEnvCollisions_MultipleCollisions(t *testing.T) {
	serviceEnv := map[string]string{"A": "1", "B": "2"}
	envInject := map[string]string{"A": "x", "B": "y", "C": "z"}
	err := CheckEnvCollisions(serviceEnv, envInject)
	if err == nil {
		t.Fatal("expected error for collisions")
	}
	if !strings.HasPrefix(err.Error(), "env_inject_service_collision:") {
		t.Errorf("expected env_inject_service_collision prefix, got: %v", err)
	}
	// Verify both colliding names are in the error message
	errStr := err.Error()
	if !strings.Contains(errStr, "A") || !strings.Contains(errStr, "B") {
		t.Errorf("error should mention both A and B: %v", err)
	}
}

func TestCheckEnvCollisions_CaseInsensitiveWindows(t *testing.T) {
	serviceEnv := map[string]string{"GITHUB_TOKEN": "fake"}
	envInject := map[string]string{"github_token": "value"}
	err := CheckEnvCollisions(serviceEnv, envInject)
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("expected collision on Windows")
		}
	} else {
		if err != nil {
			t.Fatalf("unexpected collision on POSIX: %v", err)
		}
	}
}
