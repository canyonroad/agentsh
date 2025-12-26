package k8s

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the API group and version for agentsh resources.
var GroupVersion = schema.GroupVersion{Group: "agentsh.io", Version: "v1"}

// AgentshSession represents an agentsh session in Kubernetes.
type AgentshSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentshSessionSpec   `json:"spec,omitempty"`
	Status AgentshSessionStatus `json:"status,omitempty"`
}

// AgentshSessionSpec defines the desired state of an AgentshSession.
type AgentshSessionSpec struct {
	// AgentImage is the container image for the AI agent.
	AgentImage string `json:"agentImage"`

	// PolicyRef references a policy ConfigMap.
	PolicyRef string `json:"policyRef,omitempty"`

	// Timeout is the maximum session duration.
	Timeout metav1.Duration `json:"timeout,omitempty"`

	// Resources specifies resource requirements.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Environment variables for the agent.
	Environment map[string]string `json:"environment,omitempty"`

	// ServiceAccountName is the service account to use.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// AgentshConfig overrides default agentsh configuration.
	AgentshConfig AgentshConfigOverride `json:"agentshConfig,omitempty"`
}

// AgentshConfigOverride allows overriding agentsh defaults.
type AgentshConfigOverride struct {
	// Image overrides the agentsh sidecar image.
	Image string `json:"image,omitempty"`

	// APIPort overrides the default API port.
	APIPort int `json:"apiPort,omitempty"`

	// MetricsPort overrides the default metrics port.
	MetricsPort int `json:"metricsPort,omitempty"`

	// Resources overrides resource requirements for the sidecar.
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

// AgentshSessionStatus defines the observed state of an AgentshSession.
type AgentshSessionStatus struct {
	// State is the current session state.
	State SessionState `json:"state"`

	// StartTime is when the session started.
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// EndTime is when the session ended.
	EndTime *metav1.Time `json:"endTime,omitempty"`

	// PodName is the name of the session pod.
	PodName string `json:"podName,omitempty"`

	// Stats contains session statistics.
	Stats SessionStats `json:"stats,omitempty"`

	// Conditions represent the latest observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Message provides additional status information.
	Message string `json:"message,omitempty"`
}

// SessionState represents the state of a session.
type SessionState string

const (
	SessionStatePending   SessionState = "Pending"
	SessionStateRunning   SessionState = "Running"
	SessionStateSucceeded SessionState = "Succeeded"
	SessionStateFailed    SessionState = "Failed"
	SessionStateTimedOut  SessionState = "TimedOut"
)

// SessionStats contains session statistics.
type SessionStats struct {
	FileOperations    int64 `json:"fileOperations"`
	NetworkRequests   int64 `json:"networkRequests"`
	CommandsExecuted  int64 `json:"commandsExecuted"`
	PolicyViolations  int64 `json:"policyViolations"`
	DurationSeconds   int64 `json:"durationSeconds"`
}

// AgentshSessionList contains a list of AgentshSessions.
type AgentshSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentshSession `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (s *AgentshSession) DeepCopyObject() runtime.Object {
	return s.DeepCopy()
}

// DeepCopy creates a deep copy.
func (s *AgentshSession) DeepCopy() *AgentshSession {
	if s == nil {
		return nil
	}
	out := new(AgentshSession)
	*out = *s
	out.ObjectMeta = *s.ObjectMeta.DeepCopy()
	out.Spec = *s.Spec.DeepCopy()
	out.Status = *s.Status.DeepCopy()
	return out
}

// DeepCopy creates a deep copy of the spec.
func (s *AgentshSessionSpec) DeepCopy() *AgentshSessionSpec {
	if s == nil {
		return nil
	}
	out := new(AgentshSessionSpec)
	*out = *s
	if s.Environment != nil {
		out.Environment = make(map[string]string, len(s.Environment))
		for k, v := range s.Environment {
			out.Environment[k] = v
		}
	}
	return out
}

// DeepCopy creates a deep copy of the status.
func (s *AgentshSessionStatus) DeepCopy() *AgentshSessionStatus {
	if s == nil {
		return nil
	}
	out := new(AgentshSessionStatus)
	*out = *s
	if s.StartTime != nil {
		t := *s.StartTime
		out.StartTime = &t
	}
	if s.EndTime != nil {
		t := *s.EndTime
		out.EndTime = &t
	}
	if s.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(s.Conditions))
		copy(out.Conditions, s.Conditions)
	}
	return out
}

// DeepCopyObject implements runtime.Object.
func (l *AgentshSessionList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// DeepCopy creates a deep copy.
func (l *AgentshSessionList) DeepCopy() *AgentshSessionList {
	if l == nil {
		return nil
	}
	out := new(AgentshSessionList)
	*out = *l
	if l.Items != nil {
		out.Items = make([]AgentshSession, len(l.Items))
		for i := range l.Items {
			out.Items[i] = *l.Items[i].DeepCopy()
		}
	}
	return out
}

// Operator manages AgentshSession resources.
type Operator struct {
	sidecarConfig SidecarConfig
	injector      *SidecarInjector
	sessions      map[string]*sessionState
	mu            sync.RWMutex
	eventCh       chan OperatorEvent
	stopCh        chan struct{}
}

// sessionState tracks the state of a session.
type sessionState struct {
	session   *AgentshSession
	pod       *corev1.Pod
	startTime time.Time
	timeout   time.Duration
}

// OperatorEvent represents an event from the operator.
type OperatorEvent struct {
	Type      OperatorEventType
	Session   *AgentshSession
	Message   string
	Timestamp time.Time
}

// OperatorEventType is the type of operator event.
type OperatorEventType string

const (
	EventTypeSessionCreated   OperatorEventType = "SessionCreated"
	EventTypeSessionStarted   OperatorEventType = "SessionStarted"
	EventTypeSessionCompleted OperatorEventType = "SessionCompleted"
	EventTypeSessionFailed    OperatorEventType = "SessionFailed"
	EventTypeSessionTimedOut  OperatorEventType = "SessionTimedOut"
)

// OperatorConfig configures the operator.
type OperatorConfig struct {
	// Namespace to watch (empty for all namespaces).
	Namespace string

	// SidecarConfig for injected sidecars.
	SidecarConfig SidecarConfig

	// DefaultTimeout for sessions without explicit timeout.
	DefaultTimeout time.Duration

	// MaxConcurrentSessions limits concurrent sessions.
	MaxConcurrentSessions int
}

// DefaultOperatorConfig returns default operator configuration.
func DefaultOperatorConfig() OperatorConfig {
	return OperatorConfig{
		SidecarConfig:         DefaultSidecarConfig(),
		DefaultTimeout:        time.Hour,
		MaxConcurrentSessions: 100,
	}
}

// NewOperator creates a new operator.
func NewOperator(config OperatorConfig) *Operator {
	return &Operator{
		sidecarConfig: config.SidecarConfig,
		injector:      NewSidecarInjector(config.SidecarConfig),
		sessions:      make(map[string]*sessionState),
		eventCh:       make(chan OperatorEvent, 100),
		stopCh:        make(chan struct{}),
	}
}

// Reconcile reconciles an AgentshSession resource.
func (o *Operator) Reconcile(ctx context.Context, session *AgentshSession) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	key := fmt.Sprintf("%s/%s", session.Namespace, session.Name)

	switch session.Status.State {
	case "", SessionStatePending:
		return o.handlePending(ctx, session, key)
	case SessionStateRunning:
		return o.handleRunning(ctx, session, key)
	case SessionStateSucceeded, SessionStateFailed, SessionStateTimedOut:
		return o.handleCompleted(ctx, session, key)
	default:
		return fmt.Errorf("unknown session state: %s", session.Status.State)
	}
}

// handlePending handles a pending session.
func (o *Operator) handlePending(ctx context.Context, session *AgentshSession, key string) error {
	// Create pod for session
	pod, err := o.createSessionPod(session)
	if err != nil {
		return fmt.Errorf("creating session pod: %w", err)
	}

	// Track session
	timeout := session.Spec.Timeout.Duration
	if timeout == 0 {
		timeout = time.Hour
	}

	o.sessions[key] = &sessionState{
		session:   session,
		pod:       pod,
		startTime: time.Now(),
		timeout:   timeout,
	}

	// Update status
	session.Status.State = SessionStateRunning
	now := metav1.Now()
	session.Status.StartTime = &now
	session.Status.PodName = pod.Name

	o.emit(EventTypeSessionStarted, session, "Session started")

	return nil
}

// handleRunning handles a running session.
func (o *Operator) handleRunning(ctx context.Context, session *AgentshSession, key string) error {
	state, exists := o.sessions[key]
	if !exists {
		// Session not tracked, likely a restart
		return nil
	}

	// Check timeout
	if time.Since(state.startTime) > state.timeout {
		session.Status.State = SessionStateTimedOut
		now := metav1.Now()
		session.Status.EndTime = &now
		session.Status.Message = "Session timed out"

		o.emit(EventTypeSessionTimedOut, session, "Session timed out")
		delete(o.sessions, key)
	}

	return nil
}

// handleCompleted handles a completed session.
func (o *Operator) handleCompleted(ctx context.Context, session *AgentshSession, key string) error {
	// Clean up session state
	delete(o.sessions, key)
	return nil
}

// createSessionPod creates a pod for the session.
func (o *Operator) createSessionPod(session *AgentshSession) (*corev1.Pod, error) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("agentsh-%s", session.Name),
			Namespace: session.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "agentsh-session",
				"app.kubernetes.io/instance":   session.Name,
				"app.kubernetes.io/managed-by": "agentsh-operator",
				"agentsh.io/session":           session.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: GroupVersion.String(),
					Kind:       "AgentshSession",
					Name:       session.Name,
					UID:        session.UID,
				},
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:      "agent",
					Image:     session.Spec.AgentImage,
					Resources: session.Spec.Resources,
				},
			},
		},
	}

	// Add environment variables
	for k, v := range session.Spec.Environment {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  k,
			Value: v,
		})
	}

	// Set service account
	if session.Spec.ServiceAccountName != "" {
		pod.Spec.ServiceAccountName = session.Spec.ServiceAccountName
	}

	// Inject agentsh sidecar
	if err := o.injector.Inject(&pod.Spec); err != nil {
		return nil, err
	}

	// Add policy volume if specified
	if session.Spec.PolicyRef != "" {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "agentsh-policies",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: session.Spec.PolicyRef,
					},
				},
			},
		})

		// Mount to sidecar
		for i := range pod.Spec.Containers {
			if pod.Spec.Containers[i].Name == "agentsh" {
				pod.Spec.Containers[i].VolumeMounts = append(
					pod.Spec.Containers[i].VolumeMounts,
					corev1.VolumeMount{
						Name:      "agentsh-policies",
						MountPath: o.sidecarConfig.PolicyDir,
						ReadOnly:  true,
					},
				)
			}
		}
	}

	return pod, nil
}

// Events returns the event channel.
func (o *Operator) Events() <-chan OperatorEvent {
	return o.eventCh
}

// emit sends an event.
func (o *Operator) emit(eventType OperatorEventType, session *AgentshSession, message string) {
	select {
	case o.eventCh <- OperatorEvent{
		Type:      eventType,
		Session:   session.DeepCopy(),
		Message:   message,
		Timestamp: time.Now(),
	}:
	default:
		// Channel full, drop event
	}
}

// ListSessions returns all tracked sessions.
func (o *Operator) ListSessions() []*AgentshSession {
	o.mu.RLock()
	defer o.mu.RUnlock()

	sessions := make([]*AgentshSession, 0, len(o.sessions))
	for _, state := range o.sessions {
		sessions = append(sessions, state.session.DeepCopy())
	}
	return sessions
}

// GetSession returns a specific session.
func (o *Operator) GetSession(namespace, name string) (*AgentshSession, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	state, exists := o.sessions[key]
	if !exists {
		return nil, false
	}
	return state.session.DeepCopy(), true
}

// TerminateSession terminates a session.
func (o *Operator) TerminateSession(ctx context.Context, namespace, name, reason string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	state, exists := o.sessions[key]
	if !exists {
		return fmt.Errorf("session not found: %s", key)
	}

	state.session.Status.State = SessionStateFailed
	now := metav1.Now()
	state.session.Status.EndTime = &now
	state.session.Status.Message = reason

	o.emit(EventTypeSessionFailed, state.session, reason)
	delete(o.sessions, key)

	return nil
}

// Close closes the operator.
func (o *Operator) Close() {
	close(o.stopCh)
	close(o.eventCh)
}
