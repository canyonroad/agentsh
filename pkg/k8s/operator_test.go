package k8s

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGroupVersion(t *testing.T) {
	if GroupVersion.Group != "agentsh.io" {
		t.Errorf("Group = %q, want agentsh.io", GroupVersion.Group)
	}

	if GroupVersion.Version != "v1" {
		t.Errorf("Version = %q, want v1", GroupVersion.Version)
	}
}

func TestDefaultOperatorConfig(t *testing.T) {
	config := DefaultOperatorConfig()

	if config.DefaultTimeout != time.Hour {
		t.Errorf("DefaultTimeout = %v, want 1h", config.DefaultTimeout)
	}

	if config.MaxConcurrentSessions != 100 {
		t.Errorf("MaxConcurrentSessions = %d, want 100", config.MaxConcurrentSessions)
	}
}

func TestNewOperator(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	if op == nil {
		t.Fatal("expected non-nil operator")
	}
}

func TestOperator_ListSessions_Empty(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	sessions := op.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("session count = %d, want 0", len(sessions))
	}
}

func TestOperator_GetSession_NotFound(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	_, found := op.GetSession("default", "nonexistent")
	if found {
		t.Error("should not find nonexistent session")
	}
}

func TestOperator_Reconcile_Pending(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
		},
		Status: AgentshSessionStatus{
			State: SessionStatePending,
		},
	}

	ctx := context.Background()
	err := op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Session should be running
	if session.Status.State != SessionStateRunning {
		t.Errorf("State = %v, want Running", session.Status.State)
	}

	// Should have start time
	if session.Status.StartTime == nil {
		t.Error("StartTime should not be nil")
	}

	// Should have pod name
	if session.Status.PodName == "" {
		t.Error("PodName should not be empty")
	}
}

func TestOperator_Reconcile_Running(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
		},
		Status: AgentshSessionStatus{
			State: SessionStatePending,
		},
	}

	ctx := context.Background()

	// First reconcile to start
	err := op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Second reconcile while running
	err = op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Should still be running
	if session.Status.State != SessionStateRunning {
		t.Errorf("State = %v, want Running", session.Status.State)
	}
}

func TestOperator_Reconcile_Timeout(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
			Timeout:    metav1.Duration{Duration: 1 * time.Millisecond},
		},
		Status: AgentshSessionStatus{
			State: SessionStatePending,
		},
	}

	ctx := context.Background()

	// First reconcile to start
	err := op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Wait for timeout
	time.Sleep(10 * time.Millisecond)

	// Reconcile again - should timeout
	err = op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	if session.Status.State != SessionStateTimedOut {
		t.Errorf("State = %v, want TimedOut", session.Status.State)
	}

	if session.Status.EndTime == nil {
		t.Error("EndTime should not be nil")
	}
}

func TestOperator_Reconcile_Completed(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Status: AgentshSessionStatus{
			State: SessionStateSucceeded,
		},
	}

	ctx := context.Background()
	err := op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// State should remain unchanged
	if session.Status.State != SessionStateSucceeded {
		t.Errorf("State = %v, want Succeeded", session.Status.State)
	}
}

func TestOperator_Reconcile_UnknownState(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Status: AgentshSessionStatus{
			State: "Unknown",
		},
	}

	ctx := context.Background()
	err := op.Reconcile(ctx, session)
	if err == nil {
		t.Error("should error on unknown state")
	}
}

func TestOperator_TerminateSession(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
		},
		Status: AgentshSessionStatus{
			State: SessionStatePending,
		},
	}

	ctx := context.Background()

	// Start session
	err := op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Terminate
	err = op.TerminateSession(ctx, "default", "test-session", "test termination")
	if err != nil {
		t.Fatalf("TerminateSession error: %v", err)
	}

	// Session should no longer be tracked
	_, found := op.GetSession("default", "test-session")
	if found {
		t.Error("session should not be found after termination")
	}
}

func TestOperator_TerminateSession_NotFound(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	ctx := context.Background()
	err := op.TerminateSession(ctx, "default", "nonexistent", "test")
	if err == nil {
		t.Error("should error when session not found")
	}
}

func TestOperator_Events(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	events := op.Events()
	if events == nil {
		t.Fatal("Events channel should not be nil")
	}

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
		},
		Status: AgentshSessionStatus{
			State: SessionStatePending,
		},
	}

	ctx := context.Background()
	op.Reconcile(ctx, session)

	// Should receive event
	select {
	case event := <-events:
		if event.Type != EventTypeSessionStarted {
			t.Errorf("event type = %v, want SessionStarted", event.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("should receive event")
	}
}

func TestOperator_Close(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	// Should not panic
	op.Close()
}

func TestAgentshSession_DeepCopy(t *testing.T) {
	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
			Environment: map[string]string{
				"KEY": "value",
			},
		},
		Status: AgentshSessionStatus{
			State: SessionStateRunning,
		},
	}

	copy := session.DeepCopy()

	if copy.Name != session.Name {
		t.Errorf("Name = %q, want %q", copy.Name, session.Name)
	}

	if copy.Spec.AgentImage != session.Spec.AgentImage {
		t.Errorf("AgentImage = %q, want %q", copy.Spec.AgentImage, session.Spec.AgentImage)
	}

	// Modify copy, original should be unchanged
	copy.Spec.Environment["KEY"] = "modified"
	if session.Spec.Environment["KEY"] == "modified" {
		t.Error("original should not be modified")
	}
}

func TestAgentshSession_DeepCopyObject(t *testing.T) {
	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
	}

	obj := session.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject should not return nil")
	}

	copy, ok := obj.(*AgentshSession)
	if !ok {
		t.Fatal("should return *AgentshSession")
	}

	if copy.Name != session.Name {
		t.Errorf("Name = %q, want %q", copy.Name, session.Name)
	}
}

func TestAgentshSessionList_DeepCopy(t *testing.T) {
	list := &AgentshSessionList{
		Items: []AgentshSession{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "session-1"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "session-2"},
			},
		},
	}

	copy := list.DeepCopy()

	if len(copy.Items) != 2 {
		t.Errorf("Items count = %d, want 2", len(copy.Items))
	}

	if copy.Items[0].Name != "session-1" {
		t.Errorf("Items[0].Name = %q, want session-1", copy.Items[0].Name)
	}
}

func TestAgentshSessionList_DeepCopyObject(t *testing.T) {
	list := &AgentshSessionList{
		Items: []AgentshSession{
			{ObjectMeta: metav1.ObjectMeta{Name: "test"}},
		},
	}

	obj := list.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject should not return nil")
	}

	copy, ok := obj.(*AgentshSessionList)
	if !ok {
		t.Fatal("should return *AgentshSessionList")
	}

	if len(copy.Items) != 1 {
		t.Errorf("Items count = %d, want 1", len(copy.Items))
	}
}

func TestSessionStates(t *testing.T) {
	states := []SessionState{
		SessionStatePending,
		SessionStateRunning,
		SessionStateSucceeded,
		SessionStateFailed,
		SessionStateTimedOut,
	}

	for _, s := range states {
		if string(s) == "" {
			t.Error("state should not be empty string")
		}
	}
}

func TestOperatorEventTypes(t *testing.T) {
	types := []OperatorEventType{
		EventTypeSessionCreated,
		EventTypeSessionStarted,
		EventTypeSessionCompleted,
		EventTypeSessionFailed,
		EventTypeSessionTimedOut,
	}

	for _, et := range types {
		if string(et) == "" {
			t.Error("event type should not be empty string")
		}
	}
}

func TestOperator_CreateSessionPod(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			UID:       "test-uid-123",
		},
		Spec: AgentshSessionSpec{
			AgentImage:         "my-agent:latest",
			PolicyRef:          "my-policy",
			ServiceAccountName: "my-sa",
			Environment: map[string]string{
				"API_KEY": "secret",
			},
		},
	}

	pod, err := op.createSessionPod(session)
	if err != nil {
		t.Fatalf("createSessionPod error: %v", err)
	}

	// Check pod name
	if pod.Name != "agentsh-test-session" {
		t.Errorf("Pod.Name = %q, want agentsh-test-session", pod.Name)
	}

	// Check namespace
	if pod.Namespace != "default" {
		t.Errorf("Pod.Namespace = %q, want default", pod.Namespace)
	}

	// Check labels
	if pod.Labels["agentsh.io/session"] != "test-session" {
		t.Errorf("session label = %q, want test-session", pod.Labels["agentsh.io/session"])
	}

	// Check service account
	if pod.Spec.ServiceAccountName != "my-sa" {
		t.Errorf("ServiceAccountName = %q, want my-sa", pod.Spec.ServiceAccountName)
	}

	// Check policy volume
	hasPolicyVolume := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == "agentsh-policies" {
			hasPolicyVolume = true
			if v.ConfigMap.Name != "my-policy" {
				t.Errorf("policy ConfigMap = %q, want my-policy", v.ConfigMap.Name)
			}
		}
	}
	if !hasPolicyVolume {
		t.Error("policy volume should be present")
	}

	// Check environment
	hasEnv := false
	for _, c := range pod.Spec.Containers {
		if c.Name == "agent" {
			for _, e := range c.Env {
				if e.Name == "API_KEY" && e.Value == "secret" {
					hasEnv = true
				}
			}
		}
	}
	if !hasEnv {
		t.Error("agent container should have environment variable")
	}
}

func TestAgentshSessionStatus_DeepCopy_WithTimes(t *testing.T) {
	now := metav1.Now()
	status := &AgentshSessionStatus{
		State:     SessionStateRunning,
		StartTime: &now,
		EndTime:   &now,
		Conditions: []metav1.Condition{
			{Type: "Ready", Status: metav1.ConditionTrue},
		},
	}

	copy := status.DeepCopy()

	if copy.StartTime == nil {
		t.Fatal("StartTime should not be nil")
	}

	if copy.EndTime == nil {
		t.Fatal("EndTime should not be nil")
	}

	if len(copy.Conditions) != 1 {
		t.Errorf("Conditions count = %d, want 1", len(copy.Conditions))
	}
}

func TestAgentshSessionSpec_DeepCopy_NilEnvironment(t *testing.T) {
	spec := &AgentshSessionSpec{
		AgentImage: "test:latest",
	}

	copy := spec.DeepCopy()

	if copy.AgentImage != "test:latest" {
		t.Errorf("AgentImage = %q, want test:latest", copy.AgentImage)
	}

	if copy.Environment != nil {
		t.Error("Environment should be nil when original is nil")
	}
}

func TestOperator_ListSessions_AfterReconcile(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	sessions := []*AgentshSession{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default", UID: "uid-1"},
			Spec:       AgentshSessionSpec{AgentImage: "agent:v1"},
			Status:     AgentshSessionStatus{State: SessionStatePending},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default", UID: "uid-2"},
			Spec:       AgentshSessionSpec{AgentImage: "agent:v2"},
			Status:     AgentshSessionStatus{State: SessionStatePending},
		},
	}

	ctx := context.Background()
	for _, s := range sessions {
		op.Reconcile(ctx, s)
	}

	listed := op.ListSessions()
	if len(listed) != 2 {
		t.Errorf("session count = %d, want 2", len(listed))
	}
}

func TestNilDeepCopy(t *testing.T) {
	var session *AgentshSession
	if session.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}

	var list *AgentshSessionList
	if list.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}

	var spec *AgentshSessionSpec
	if spec.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}

	var status *AgentshSessionStatus
	if status.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

func TestOperator_GetSession_AfterReconcile(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "test-ns",
			UID:       "test-uid",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
		},
		Status: AgentshSessionStatus{
			State: SessionStatePending,
		},
	}

	ctx := context.Background()
	op.Reconcile(ctx, session)

	retrieved, found := op.GetSession("test-ns", "test-session")
	if !found {
		t.Fatal("session should be found")
	}

	if retrieved.Name != "test-session" {
		t.Errorf("Name = %q, want test-session", retrieved.Name)
	}

	if retrieved.Status.State != SessionStateRunning {
		t.Errorf("State = %v, want Running", retrieved.Status.State)
	}
}

func TestEmptyReconcile(t *testing.T) {
	config := DefaultOperatorConfig()
	op := NewOperator(config)

	session := &AgentshSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: AgentshSessionSpec{
			AgentImage: "my-agent:latest",
		},
		Status: AgentshSessionStatus{
			State: "", // Empty state should be treated as Pending
		},
	}

	ctx := context.Background()
	err := op.Reconcile(ctx, session)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	if session.Status.State != SessionStateRunning {
		t.Errorf("State = %v, want Running", session.Status.State)
	}
}
