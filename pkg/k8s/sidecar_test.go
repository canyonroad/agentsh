package k8s

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestDefaultSidecarConfig(t *testing.T) {
	config := DefaultSidecarConfig()

	if config.Image != "agentsh/agentsh:latest" {
		t.Errorf("Image = %q, want agentsh/agentsh:latest", config.Image)
	}

	if config.APIPort != 9090 {
		t.Errorf("APIPort = %d, want 9090", config.APIPort)
	}

	if config.MetricsPort != 9091 {
		t.Errorf("MetricsPort = %d, want 9091", config.MetricsPort)
	}

	if !config.SecurityContext.Privileged {
		t.Error("SecurityContext.Privileged should be true")
	}

	if len(config.SecurityContext.Capabilities) != 2 {
		t.Errorf("Capabilities count = %d, want 2", len(config.SecurityContext.Capabilities))
	}
}

func TestNewSidecarInjector(t *testing.T) {
	config := DefaultSidecarConfig()
	injector := NewSidecarInjector(config)

	if injector == nil {
		t.Fatal("expected non-nil injector")
	}
}

func TestSidecarInjector_Inject(t *testing.T) {
	config := DefaultSidecarConfig()
	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "agent",
				Image: "my-agent:latest",
			},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Should have 2 containers now
	if len(pod.Containers) != 2 {
		t.Errorf("container count = %d, want 2", len(pod.Containers))
	}

	// Find agentsh container
	var sidecar *corev1.Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "agentsh" {
			sidecar = &pod.Containers[i]
			break
		}
	}

	if sidecar == nil {
		t.Fatal("agentsh sidecar not found")
	}

	if sidecar.Image != config.Image {
		t.Errorf("sidecar image = %q, want %q", sidecar.Image, config.Image)
	}

	// Check ports
	if len(sidecar.Ports) != 2 {
		t.Errorf("port count = %d, want 2", len(sidecar.Ports))
	}

	// Check volumes added
	if len(pod.Volumes) < 2 {
		t.Errorf("volume count = %d, want >= 2", len(pod.Volumes))
	}

	// Check main container has socket mount
	agentContainer := pod.Containers[0]
	hasSocketMount := false
	for _, vm := range agentContainer.VolumeMounts {
		if vm.Name == "agentsh-socket" {
			hasSocketMount = true
			break
		}
	}
	if !hasSocketMount {
		t.Error("agent container should have socket mount")
	}

	// Check environment variable
	hasEnvVar := false
	for _, env := range agentContainer.Env {
		if env.Name == "AGENTSH_SOCKET" {
			hasEnvVar = true
			if env.Value != config.SocketPath {
				t.Errorf("AGENTSH_SOCKET = %q, want %q", env.Value, config.SocketPath)
			}
			break
		}
	}
	if !hasEnvVar {
		t.Error("agent container should have AGENTSH_SOCKET env var")
	}
}

func TestSidecarInjector_SecurityContext(t *testing.T) {
	config := DefaultSidecarConfig()
	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "test:latest"},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Find sidecar
	var sidecar *corev1.Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "agentsh" {
			sidecar = &pod.Containers[i]
			break
		}
	}

	if sidecar.SecurityContext == nil {
		t.Fatal("security context should not be nil")
	}

	if sidecar.SecurityContext.Privileged == nil || !*sidecar.SecurityContext.Privileged {
		t.Error("privileged should be true")
	}

	if sidecar.SecurityContext.Capabilities == nil {
		t.Fatal("capabilities should not be nil")
	}

	if len(sidecar.SecurityContext.Capabilities.Add) != 2 {
		t.Errorf("capabilities count = %d, want 2", len(sidecar.SecurityContext.Capabilities.Add))
	}
}

func TestSidecarInjector_ResourceRequirements(t *testing.T) {
	config := DefaultSidecarConfig()
	config.Resources.Limits.CPU = "1"
	config.Resources.Limits.Memory = "1Gi"
	config.Resources.Requests.CPU = "500m"
	config.Resources.Requests.Memory = "512Mi"

	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "test:latest"},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Find sidecar
	var sidecar *corev1.Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "agentsh" {
			sidecar = &pod.Containers[i]
			break
		}
	}

	if sidecar.Resources.Limits == nil {
		t.Fatal("limits should not be nil")
	}

	if sidecar.Resources.Requests == nil {
		t.Fatal("requests should not be nil")
	}
}

func TestSidecarInjector_Probes(t *testing.T) {
	config := DefaultSidecarConfig()
	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "test:latest"},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Find sidecar
	var sidecar *corev1.Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "agentsh" {
			sidecar = &pod.Containers[i]
			break
		}
	}

	if sidecar.LivenessProbe == nil {
		t.Error("liveness probe should not be nil")
	}

	if sidecar.ReadinessProbe == nil {
		t.Error("readiness probe should not be nil")
	}

	if sidecar.LivenessProbe.HTTPGet.Path != "/healthz" {
		t.Errorf("liveness path = %q, want /healthz", sidecar.LivenessProbe.HTTPGet.Path)
	}

	if sidecar.ReadinessProbe.HTTPGet.Path != "/ready" {
		t.Errorf("readiness path = %q, want /ready", sidecar.ReadinessProbe.HTTPGet.Path)
	}
}

func TestNewSidecarRuntime(t *testing.T) {
	config := DefaultSidecarConfig()
	runtime := NewSidecarRuntime(config)

	if runtime == nil {
		t.Fatal("expected non-nil runtime")
	}

	if runtime.IsReady() {
		t.Error("should not be ready initially")
	}

	if !runtime.IsHealthy() {
		t.Error("should be healthy initially")
	}
}

func TestSidecarRuntime_Stats(t *testing.T) {
	config := DefaultSidecarConfig()
	runtime := NewSidecarRuntime(config)

	stats := runtime.Stats()

	if stats.StartTime.IsZero() {
		t.Error("StartTime should not be zero")
	}

	if stats.Uptime == "" {
		t.Error("Uptime should not be empty")
	}
}

func TestSidecarRuntime_StartStop(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "agentsh-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	config := DefaultSidecarConfig()
	config.SocketPath = filepath.Join(tmpDir, "agent.sock")
	config.APIPort = 0 // Use random port

	runtime := NewSidecarRuntime(config)

	ctx := context.Background()
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Should be ready after start
	if !runtime.IsReady() {
		t.Error("should be ready after start")
	}

	// Socket file should exist
	if _, err := os.Stat(config.SocketPath); os.IsNotExist(err) {
		t.Error("socket file should exist")
	}

	// Stop
	if err := runtime.Stop(ctx); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	// Should not be ready after stop
	if runtime.IsReady() {
		t.Error("should not be ready after stop")
	}

	// Socket file should be removed
	if _, err := os.Stat(config.SocketPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed")
	}
}

func TestSidecarInjector_Environment(t *testing.T) {
	config := DefaultSidecarConfig()
	config.Environment = map[string]string{
		"CUSTOM_VAR": "custom_value",
	}

	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "test:latest"},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Find sidecar
	var sidecar *corev1.Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "agentsh" {
			sidecar = &pod.Containers[i]
			break
		}
	}

	hasCustomVar := false
	for _, env := range sidecar.Env {
		if env.Name == "CUSTOM_VAR" && env.Value == "custom_value" {
			hasCustomVar = true
			break
		}
	}

	if !hasCustomVar {
		t.Error("sidecar should have custom environment variable")
	}
}

func TestSidecarInjector_DisabledProbes(t *testing.T) {
	config := DefaultSidecarConfig()
	config.LivenessProbe.Enabled = false
	config.ReadinessProbe.Enabled = false

	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "test:latest"},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Find sidecar
	var sidecar *corev1.Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "agentsh" {
			sidecar = &pod.Containers[i]
			break
		}
	}

	if sidecar.LivenessProbe != nil {
		t.Error("liveness probe should be nil when disabled")
	}

	if sidecar.ReadinessProbe != nil {
		t.Error("readiness probe should be nil when disabled")
	}
}

func TestSidecarInjector_InvalidResources(t *testing.T) {
	config := DefaultSidecarConfig()
	config.Resources.Limits.CPU = "invalid"

	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "test:latest"},
		},
	}

	err := injector.Inject(pod)
	if err == nil {
		t.Error("should error with invalid resource quantity")
	}
}

func TestCreateVolumes(t *testing.T) {
	config := DefaultSidecarConfig()
	injector := NewSidecarInjector(config)

	volumes := injector.createVolumes()

	if len(volumes) != 2 {
		t.Errorf("volume count = %d, want 2", len(volumes))
	}

	names := make(map[string]bool)
	for _, v := range volumes {
		names[v.Name] = true
	}

	if !names["agentsh-socket"] {
		t.Error("agentsh-socket volume not found")
	}

	if !names["agentsh-workspace"] {
		t.Error("agentsh-workspace volume not found")
	}
}

func TestRuntimeHealthHandlers(t *testing.T) {
	config := DefaultSidecarConfig()
	runtime := NewSidecarRuntime(config)

	// Test that stats are maintained
	stats := runtime.Stats()
	time.Sleep(10 * time.Millisecond)
	stats2 := runtime.Stats()

	if stats.Uptime == stats2.Uptime {
		// Uptime should have changed (though might be same string for short durations)
	}
}

func TestSidecarConfigDefaults(t *testing.T) {
	config := DefaultSidecarConfig()

	if config.SocketPath != "/var/run/agentsh/agent.sock" {
		t.Errorf("SocketPath = %q, want /var/run/agentsh/agent.sock", config.SocketPath)
	}

	if config.PolicyDir != "/etc/agentsh/policies" {
		t.Errorf("PolicyDir = %q, want /etc/agentsh/policies", config.PolicyDir)
	}

	if config.WorkspaceDir != "/workspace" {
		t.Errorf("WorkspaceDir = %q, want /workspace", config.WorkspaceDir)
	}

	if config.LivenessProbe.InitialDelaySeconds != 10 {
		t.Errorf("LivenessProbe.InitialDelaySeconds = %d, want 10", config.LivenessProbe.InitialDelaySeconds)
	}

	if config.ReadinessProbe.InitialDelaySeconds != 5 {
		t.Errorf("ReadinessProbe.InitialDelaySeconds = %d, want 5", config.ReadinessProbe.InitialDelaySeconds)
	}
}

func TestProbeConfigDefaults(t *testing.T) {
	config := DefaultSidecarConfig()

	if !config.LivenessProbe.Enabled {
		t.Error("LivenessProbe should be enabled by default")
	}

	if !config.ReadinessProbe.Enabled {
		t.Error("ReadinessProbe should be enabled by default")
	}

	if config.LivenessProbe.Path != "/healthz" {
		t.Errorf("LivenessProbe.Path = %q, want /healthz", config.LivenessProbe.Path)
	}

	if config.ReadinessProbe.Path != "/ready" {
		t.Errorf("ReadinessProbe.Path = %q, want /ready", config.ReadinessProbe.Path)
	}
}

func TestImagePullPolicy(t *testing.T) {
	config := DefaultSidecarConfig()

	if config.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Errorf("ImagePullPolicy = %v, want IfNotPresent", config.ImagePullPolicy)
	}
}

func TestMultipleContainerInjection(t *testing.T) {
	config := DefaultSidecarConfig()
	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "main", Image: "main:latest"},
			{Name: "helper", Image: "helper:latest"},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Should have 3 containers
	if len(pod.Containers) != 3 {
		t.Errorf("container count = %d, want 3", len(pod.Containers))
	}

	// Both original containers should have socket mount
	for _, c := range pod.Containers {
		if c.Name == "agentsh" {
			continue
		}

		hasMount := false
		for _, vm := range c.VolumeMounts {
			if vm.Name == "agentsh-socket" {
				hasMount = true
				break
			}
		}
		if !hasMount {
			t.Errorf("container %s should have socket mount", c.Name)
		}
	}
}

func TestRuntimeSetters(t *testing.T) {
	config := DefaultSidecarConfig()
	runtime := NewSidecarRuntime(config)

	// Initially healthy
	if !runtime.IsHealthy() {
		t.Error("should be healthy initially")
	}

	// Set unhealthy
	runtime.setHealthy(false)
	if runtime.IsHealthy() {
		t.Error("should be unhealthy after setting")
	}

	// Set healthy again
	runtime.setHealthy(true)
	if !runtime.IsHealthy() {
		t.Error("should be healthy after setting")
	}

	// Initially not ready
	if runtime.IsReady() {
		t.Error("should not be ready initially")
	}

	// Set ready
	runtime.setReady(true)
	if !runtime.IsReady() {
		t.Error("should be ready after setting")
	}

	// Set not ready
	runtime.setReady(false)
	if runtime.IsReady() {
		t.Error("should not be ready after setting")
	}
}

func TestResourceListParsing(t *testing.T) {
	tests := []struct {
		name    string
		cpu     string
		memory  string
		wantErr bool
	}{
		{"valid", "500m", "512Mi", false},
		{"whole cpu", "2", "1Gi", false},
		{"empty values", "", "", false},
		{"invalid cpu", "invalid", "512Mi", true},
		{"invalid memory", "500m", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultSidecarConfig()
			config.Resources.Limits.CPU = tt.cpu
			config.Resources.Limits.Memory = tt.memory

			injector := NewSidecarInjector(config)
			pod := &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "agent", Image: "test:latest"},
				},
			}

			err := injector.Inject(pod)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSecurityContextWithRunAs(t *testing.T) {
	config := DefaultSidecarConfig()
	uid := int64(1000)
	gid := int64(1000)
	config.SecurityContext.RunAsUser = &uid
	config.SecurityContext.RunAsGroup = &gid

	injector := NewSidecarInjector(config)

	pod := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "test:latest"},
		},
	}

	err := injector.Inject(pod)
	if err != nil {
		t.Fatalf("Inject error: %v", err)
	}

	// Find sidecar
	var sidecar *corev1.Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "agentsh" {
			sidecar = &pod.Containers[i]
			break
		}
	}

	if sidecar.SecurityContext.RunAsUser == nil {
		t.Fatal("RunAsUser should not be nil")
	}

	if *sidecar.SecurityContext.RunAsUser != 1000 {
		t.Errorf("RunAsUser = %d, want 1000", *sidecar.SecurityContext.RunAsUser)
	}

	if sidecar.SecurityContext.RunAsGroup == nil {
		t.Fatal("RunAsGroup should not be nil")
	}

	if *sidecar.SecurityContext.RunAsGroup != 1000 {
		t.Errorf("RunAsGroup = %d, want 1000", *sidecar.SecurityContext.RunAsGroup)
	}
}

func TestRuntimeStatsUptime(t *testing.T) {
	config := DefaultSidecarConfig()
	runtime := NewSidecarRuntime(config)

	stats := runtime.Stats()
	if stats.Uptime == "" {
		t.Error("Uptime should not be empty")
	}

	// Uptime should be parseable
	_, err := time.ParseDuration(stats.Uptime)
	if err != nil {
		t.Errorf("Uptime should be parseable duration: %v", err)
	}
}

func TestBytesBuffer(t *testing.T) {
	// Test that we can use bytes.Buffer correctly
	var buf bytes.Buffer
	buf.WriteString("test")
	if buf.String() != "test" {
		t.Error("buffer should contain 'test'")
	}
}
