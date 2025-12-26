package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// SidecarConfig configures the agentsh sidecar container.
type SidecarConfig struct {
	// Image is the agentsh container image.
	Image string `yaml:"image" json:"image"`

	// ImagePullPolicy is the image pull policy.
	ImagePullPolicy corev1.PullPolicy `yaml:"image_pull_policy" json:"image_pull_policy"`

	// SocketPath is the path to the Unix socket for agent communication.
	SocketPath string `yaml:"socket_path" json:"socket_path"`

	// PolicyDir is the directory containing policy files.
	PolicyDir string `yaml:"policy_dir" json:"policy_dir"`

	// WorkspaceDir is the shared workspace directory.
	WorkspaceDir string `yaml:"workspace_dir" json:"workspace_dir"`

	// APIPort is the port for the control API.
	APIPort int `yaml:"api_port" json:"api_port"`

	// MetricsPort is the port for Prometheus metrics.
	MetricsPort int `yaml:"metrics_port" json:"metrics_port"`

	// Resources specifies resource requirements.
	Resources ResourceRequirements `yaml:"resources" json:"resources"`

	// SecurityContext specifies security settings.
	SecurityContext SidecarSecurityContext `yaml:"security_context" json:"security_context"`

	// Environment variables to inject.
	Environment map[string]string `yaml:"environment" json:"environment"`

	// LivenessProbe configuration.
	LivenessProbe ProbeConfig `yaml:"liveness_probe" json:"liveness_probe"`

	// ReadinessProbe configuration.
	ReadinessProbe ProbeConfig `yaml:"readiness_probe" json:"readiness_probe"`
}

// ResourceRequirements specifies container resource requirements.
type ResourceRequirements struct {
	Limits   ResourceList `yaml:"limits" json:"limits"`
	Requests ResourceList `yaml:"requests" json:"requests"`
}

// ResourceList is a map of resource name to quantity.
type ResourceList struct {
	CPU    string `yaml:"cpu" json:"cpu"`
	Memory string `yaml:"memory" json:"memory"`
}

// SidecarSecurityContext specifies security settings for the sidecar.
type SidecarSecurityContext struct {
	Privileged   bool     `yaml:"privileged" json:"privileged"`
	Capabilities []string `yaml:"capabilities" json:"capabilities"`
	RunAsUser    *int64   `yaml:"run_as_user,omitempty" json:"run_as_user,omitempty"`
	RunAsGroup   *int64   `yaml:"run_as_group,omitempty" json:"run_as_group,omitempty"`
}

// ProbeConfig configures health probes.
type ProbeConfig struct {
	Enabled             bool   `yaml:"enabled" json:"enabled"`
	Path                string `yaml:"path" json:"path"`
	InitialDelaySeconds int    `yaml:"initial_delay_seconds" json:"initial_delay_seconds"`
	PeriodSeconds       int    `yaml:"period_seconds" json:"period_seconds"`
	TimeoutSeconds      int    `yaml:"timeout_seconds" json:"timeout_seconds"`
	FailureThreshold    int    `yaml:"failure_threshold" json:"failure_threshold"`
}

// DefaultSidecarConfig returns a default sidecar configuration.
func DefaultSidecarConfig() SidecarConfig {
	return SidecarConfig{
		Image:           "agentsh/agentsh:latest",
		ImagePullPolicy: corev1.PullIfNotPresent,
		SocketPath:      "/var/run/agentsh/agent.sock",
		PolicyDir:       "/etc/agentsh/policies",
		WorkspaceDir:    "/workspace",
		APIPort:         9090,
		MetricsPort:     9091,
		Resources: ResourceRequirements{
			Limits: ResourceList{
				CPU:    "500m",
				Memory: "512Mi",
			},
			Requests: ResourceList{
				CPU:    "100m",
				Memory: "128Mi",
			},
		},
		SecurityContext: SidecarSecurityContext{
			Privileged:   true,
			Capabilities: []string{"SYS_ADMIN", "NET_ADMIN"},
		},
		LivenessProbe: ProbeConfig{
			Enabled:             true,
			Path:                "/healthz",
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			TimeoutSeconds:      5,
			FailureThreshold:    3,
		},
		ReadinessProbe: ProbeConfig{
			Enabled:             true,
			Path:                "/ready",
			InitialDelaySeconds: 5,
			PeriodSeconds:       5,
			TimeoutSeconds:      3,
			FailureThreshold:    3,
		},
	}
}

// SidecarInjector injects agentsh sidecar into pod specifications.
type SidecarInjector struct {
	config SidecarConfig
}

// NewSidecarInjector creates a new sidecar injector.
func NewSidecarInjector(config SidecarConfig) *SidecarInjector {
	return &SidecarInjector{config: config}
}

// Inject adds the agentsh sidecar to a pod spec.
func (s *SidecarInjector) Inject(pod *corev1.PodSpec) error {
	// Add volumes
	pod.Volumes = append(pod.Volumes, s.createVolumes()...)

	// Create sidecar container
	sidecar, err := s.createSidecarContainer()
	if err != nil {
		return fmt.Errorf("creating sidecar container: %w", err)
	}

	// Add sidecar container
	pod.Containers = append(pod.Containers, *sidecar)

	// Update main container(s) with socket mount
	for i := range pod.Containers {
		if pod.Containers[i].Name != "agentsh" {
			s.addSocketMount(&pod.Containers[i])
		}
	}

	return nil
}

// createVolumes creates the required volumes.
func (s *SidecarInjector) createVolumes() []corev1.Volume {
	return []corev1.Volume{
		{
			Name: "agentsh-socket",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "agentsh-workspace",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}
}

// createSidecarContainer creates the agentsh sidecar container.
func (s *SidecarInjector) createSidecarContainer() (*corev1.Container, error) {
	container := &corev1.Container{
		Name:            "agentsh",
		Image:           s.config.Image,
		ImagePullPolicy: s.config.ImagePullPolicy,
		Ports: []corev1.ContainerPort{
			{
				Name:          "api",
				ContainerPort: int32(s.config.APIPort),
				Protocol:      corev1.ProtocolTCP,
			},
			{
				Name:          "metrics",
				ContainerPort: int32(s.config.MetricsPort),
				Protocol:      corev1.ProtocolTCP,
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "agentsh-socket",
				MountPath: filepath.Dir(s.config.SocketPath),
			},
			{
				Name:      "agentsh-workspace",
				MountPath: s.config.WorkspaceDir,
			},
		},
		SecurityContext: s.createSecurityContext(),
	}

	// Add resources
	resources, err := s.createResourceRequirements()
	if err != nil {
		return nil, err
	}
	container.Resources = *resources

	// Add environment variables
	for k, v := range s.config.Environment {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  k,
			Value: v,
		})
	}

	// Add probes
	if s.config.LivenessProbe.Enabled {
		container.LivenessProbe = s.createProbe(s.config.LivenessProbe)
	}
	if s.config.ReadinessProbe.Enabled {
		container.ReadinessProbe = s.createProbe(s.config.ReadinessProbe)
	}

	return container, nil
}

// createSecurityContext creates the security context.
func (s *SidecarInjector) createSecurityContext() *corev1.SecurityContext {
	sc := &corev1.SecurityContext{
		Privileged: &s.config.SecurityContext.Privileged,
	}

	if len(s.config.SecurityContext.Capabilities) > 0 {
		caps := make([]corev1.Capability, len(s.config.SecurityContext.Capabilities))
		for i, c := range s.config.SecurityContext.Capabilities {
			caps[i] = corev1.Capability(c)
		}
		sc.Capabilities = &corev1.Capabilities{
			Add: caps,
		}
	}

	if s.config.SecurityContext.RunAsUser != nil {
		sc.RunAsUser = s.config.SecurityContext.RunAsUser
	}
	if s.config.SecurityContext.RunAsGroup != nil {
		sc.RunAsGroup = s.config.SecurityContext.RunAsGroup
	}

	return sc
}

// createResourceRequirements creates resource requirements.
func (s *SidecarInjector) createResourceRequirements() (*corev1.ResourceRequirements, error) {
	limits := corev1.ResourceList{}
	requests := corev1.ResourceList{}

	if s.config.Resources.Limits.CPU != "" {
		qty, err := resource.ParseQuantity(s.config.Resources.Limits.CPU)
		if err != nil {
			return nil, fmt.Errorf("parsing CPU limit: %w", err)
		}
		limits[corev1.ResourceCPU] = qty
	}

	if s.config.Resources.Limits.Memory != "" {
		qty, err := resource.ParseQuantity(s.config.Resources.Limits.Memory)
		if err != nil {
			return nil, fmt.Errorf("parsing memory limit: %w", err)
		}
		limits[corev1.ResourceMemory] = qty
	}

	if s.config.Resources.Requests.CPU != "" {
		qty, err := resource.ParseQuantity(s.config.Resources.Requests.CPU)
		if err != nil {
			return nil, fmt.Errorf("parsing CPU request: %w", err)
		}
		requests[corev1.ResourceCPU] = qty
	}

	if s.config.Resources.Requests.Memory != "" {
		qty, err := resource.ParseQuantity(s.config.Resources.Requests.Memory)
		if err != nil {
			return nil, fmt.Errorf("parsing memory request: %w", err)
		}
		requests[corev1.ResourceMemory] = qty
	}

	return &corev1.ResourceRequirements{
		Limits:   limits,
		Requests: requests,
	}, nil
}

// createProbe creates a health probe.
func (s *SidecarInjector) createProbe(config ProbeConfig) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: config.Path,
				Port: intstr.FromInt(s.config.APIPort),
			},
		},
		InitialDelaySeconds: int32(config.InitialDelaySeconds),
		PeriodSeconds:       int32(config.PeriodSeconds),
		TimeoutSeconds:      int32(config.TimeoutSeconds),
		FailureThreshold:    int32(config.FailureThreshold),
	}
}

// addSocketMount adds the socket volume mount to a container.
func (s *SidecarInjector) addSocketMount(container *corev1.Container) {
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      "agentsh-socket",
		MountPath: filepath.Dir(s.config.SocketPath),
	})

	// Add environment variable for socket path
	container.Env = append(container.Env, corev1.EnvVar{
		Name:  "AGENTSH_SOCKET",
		Value: s.config.SocketPath,
	})
}

// SidecarRuntime manages the sidecar runtime environment.
type SidecarRuntime struct {
	config   SidecarConfig
	listener net.Listener
	server   *http.Server
	mu       sync.RWMutex
	ready    bool
	healthy  bool
	stats    RuntimeStats
}

// RuntimeStats tracks sidecar runtime statistics.
type RuntimeStats struct {
	StartTime     time.Time `json:"start_time"`
	Uptime        string    `json:"uptime"`
	RequestCount  int64     `json:"request_count"`
	ErrorCount    int64     `json:"error_count"`
	ActiveAgents  int       `json:"active_agents"`
	PolicyVersion string    `json:"policy_version"`
}

// NewSidecarRuntime creates a new sidecar runtime.
func NewSidecarRuntime(config SidecarConfig) *SidecarRuntime {
	return &SidecarRuntime{
		config:  config,
		healthy: true,
		stats: RuntimeStats{
			StartTime: time.Now(),
		},
	}
}

// Start starts the sidecar runtime.
func (r *SidecarRuntime) Start(ctx context.Context) error {
	// Create socket directory
	socketDir := filepath.Dir(r.config.SocketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("creating socket directory: %w", err)
	}

	// Remove existing socket
	os.Remove(r.config.SocketPath)

	// Create Unix socket listener
	listener, err := net.Listen("unix", r.config.SocketPath)
	if err != nil {
		return fmt.Errorf("creating socket listener: %w", err)
	}
	r.listener = listener

	// Set socket permissions
	if err := os.Chmod(r.config.SocketPath, 0666); err != nil {
		return fmt.Errorf("setting socket permissions: %w", err)
	}

	// Create HTTP server for API
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", r.handleHealth)
	mux.HandleFunc("GET /ready", r.handleReady)
	mux.HandleFunc("GET /stats", r.handleStats)

	r.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", r.config.APIPort),
		Handler: mux,
	}

	// Start API server
	go func() {
		if err := r.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			r.setHealthy(false)
		}
	}()

	r.setReady(true)
	return nil
}

// Stop stops the sidecar runtime.
func (r *SidecarRuntime) Stop(ctx context.Context) error {
	r.setReady(false)

	if r.server != nil {
		if err := r.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutting down server: %w", err)
		}
	}

	if r.listener != nil {
		if err := r.listener.Close(); err != nil {
			return fmt.Errorf("closing listener: %w", err)
		}
	}

	// Remove socket file
	os.Remove(r.config.SocketPath)

	return nil
}

// IsReady returns whether the sidecar is ready.
func (r *SidecarRuntime) IsReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ready
}

// IsHealthy returns whether the sidecar is healthy.
func (r *SidecarRuntime) IsHealthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.healthy
}

// Stats returns current runtime statistics.
func (r *SidecarRuntime) Stats() RuntimeStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stats := r.stats
	stats.Uptime = time.Since(stats.StartTime).String()
	return stats
}

func (r *SidecarRuntime) setReady(ready bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = ready
}

func (r *SidecarRuntime) setHealthy(healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.healthy = healthy
}

func (r *SidecarRuntime) handleHealth(w http.ResponseWriter, req *http.Request) {
	if r.IsHealthy() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("unhealthy"))
	}
}

func (r *SidecarRuntime) handleReady(w http.ResponseWriter, req *http.Request) {
	if r.IsReady() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready"))
	}
}

func (r *SidecarRuntime) handleStats(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(r.Stats())
}
