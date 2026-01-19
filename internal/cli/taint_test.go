package cli

import (
	"bytes"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func TestPrintTaintListHuman(t *testing.T) {
	tests := []struct {
		name        string
		taints      []types.TaintInfo
		wantStrings []string
	}{
		{
			name:        "empty list",
			taints:      nil,
			wantStrings: []string{"No tainted processes"},
		},
		{
			name: "single taint",
			taints: []types.TaintInfo{
				{
					PID:         1234,
					SourcePID:   1000,
					SourceName:  "cursor",
					ContextName: "ai_tools",
					IsAgent:     false,
					Via:         []string{"bash"},
					ViaClasses:  []string{"shell"},
					Depth:       1,
					InheritedAt: time.Now(),
				},
			},
			wantStrings: []string{"1234", "cursor", "ai_tools", "bash", "1 tainted process"},
		},
		{
			name: "agent process",
			taints: []types.TaintInfo{
				{
					PID:         5678,
					SourcePID:   5000,
					SourceName:  "claude",
					ContextName: "ai_tools",
					IsAgent:     true,
					Via:         []string{"node", "npm"},
					ViaClasses:  []string{"language_runtime", "build_tool"},
					Depth:       2,
					InheritedAt: time.Now(),
				},
			},
			wantStrings: []string{"5678", "claude", "yes", "node"},
		},
		{
			name: "multiple taints",
			taints: []types.TaintInfo{
				{PID: 1, SourceName: "cursor"},
				{PID: 2, SourceName: "vscode"},
			},
			wantStrings: []string{"2 tainted process(es)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&buf)

			err := printTaintListHuman(cmd, tt.taints)
			if err != nil {
				t.Fatalf("printTaintListHuman() error = %v", err)
			}

			output := buf.String()
			for _, want := range tt.wantStrings {
				if !bytes.Contains([]byte(output), []byte(want)) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestPrintTaintShowHuman(t *testing.T) {
	taint := &types.TaintInfo{
		PID:         1234,
		SourcePID:   1000,
		SourceName:  "cursor",
		ContextName: "ai_tools",
		IsAgent:     true,
		Via:         []string{"bash", "npm", "node"},
		ViaClasses:  []string{"shell", "build_tool", "language_runtime"},
		Depth:       3,
		InheritedAt: time.Now(),
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := printTaintShowHuman(cmd, taint)
	if err != nil {
		t.Fatalf("printTaintShowHuman() error = %v", err)
	}

	output := buf.String()
	wantStrings := []string{
		"PID:          1234",
		"Source PID:   1000",
		"Source Name:  cursor",
		"Context:      ai_tools",
		"Depth:        3",
		"Is Agent:     true",
		"Via Chain:",
		"1. bash [shell]",
		"2. npm [build_tool]",
		"3. node [language_runtime]",
	}

	for _, want := range wantStrings {
		if !bytes.Contains([]byte(output), []byte(want)) {
			t.Errorf("output missing %q\ngot:\n%s", want, output)
		}
	}
}

func TestPrintTaintShowHuman_DirectChild(t *testing.T) {
	taint := &types.TaintInfo{
		PID:         1234,
		SourcePID:   1000,
		SourceName:  "cursor",
		ContextName: "ai_tools",
		Via:         []string{},
		ViaClasses:  []string{},
		Depth:       0,
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := printTaintShowHuman(cmd, taint)
	if err != nil {
		t.Fatalf("printTaintShowHuman() error = %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("(direct child of source)")) {
		t.Errorf("expected '(direct child of source)' for empty via chain\ngot:\n%s", output)
	}
}

func TestPrintTaintTraceHuman(t *testing.T) {
	trace := &types.TaintTrace{
		Taint: &types.TaintInfo{
			PID:         1234,
			SourcePID:   1000,
			SourceName:  "cursor",
			ContextName: "ai_tools",
			Via:         []string{"bash", "npm"},
			ViaClasses:  []string{"shell", "build_tool"},
			Depth:       2,
			IsAgent:     true,
		},
		MatchedRules: []types.TaintMatchedRule{
			{Name: "user_terminal", Action: "allow_normal_policy", Message: "User-opened terminal"},
		},
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := printTaintTraceHuman(cmd, trace)
	if err != nil {
		t.Fatalf("printTaintTraceHuman() error = %v", err)
	}

	output := buf.String()
	wantStrings := []string{
		"Ancestry Trace for PID 1234",
		"SOURCE: cursor (PID 1000)",
		"Context: ai_tools",
		"bash [shell]",
		"npm [build_tool]",
		"Matched Chain Rules:",
		"user_terminal: allow_normal_policy",
		"User-opened terminal",
		"AI AGENT",
	}

	for _, want := range wantStrings {
		if !bytes.Contains([]byte(output), []byte(want)) {
			t.Errorf("output missing %q\ngot:\n%s", want, output)
		}
	}
}

func TestPrintTaintTraceHuman_NilTrace(t *testing.T) {
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := printTaintTraceHuman(cmd, nil)
	if err != nil {
		t.Fatalf("printTaintTraceHuman() error = %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("not tainted")) {
		t.Errorf("expected 'not tainted' message\ngot:\n%s", output)
	}
}

func TestPrintTaintEvent(t *testing.T) {
	tests := []struct {
		name      string
		event     types.TaintEvent
		wantParts []string
	}{
		{
			name: "taint_created",
			event: types.TaintEvent{
				Type:        "taint_created",
				PID:         1234,
				SourceName:  "cursor",
				ContextName: "ai_tools",
				Timestamp:   time.Date(2024, 1, 1, 12, 30, 45, 0, time.UTC),
			},
			wantParts: []string{"TAINT SOURCE", "cursor", "1234", "ai_tools"},
		},
		{
			name: "taint_propagated",
			event: types.TaintEvent{
				Type:       "taint_propagated",
				PID:        5678,
				SourceName: "cursor",
				Depth:      3,
				Timestamp:  time.Date(2024, 1, 1, 12, 30, 45, 0, time.UTC),
			},
			wantParts: []string{"PROPAGATED", "5678", "cursor", "depth 3"},
		},
		{
			name: "taint_removed",
			event: types.TaintEvent{
				Type:      "taint_removed",
				PID:       9999,
				Timestamp: time.Date(2024, 1, 1, 12, 30, 45, 0, time.UTC),
			},
			wantParts: []string{"REMOVED", "9999"},
		},
		{
			name: "agent_detected",
			event: types.TaintEvent{
				Type:       "agent_detected",
				PID:        4321,
				Confidence: 0.95,
				Timestamp:  time.Date(2024, 1, 1, 12, 30, 45, 0, time.UTC),
			},
			wantParts: []string{"AGENT DETECTED", "4321", "95%"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&buf)

			printTaintEvent(cmd, tt.event)

			output := buf.String()
			for _, want := range tt.wantParts {
				if !bytes.Contains([]byte(output), []byte(want)) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestPrintSimulationHuman(t *testing.T) {
	result := &SimulationResult{
		Ancestry:    []string{"cursor", "bash", "npm"},
		ViaClasses:  []string{"agent", "shell", "build_tool"},
		Command:     "curl",
		Args:        []string{"https://example.com"},
		ContextName: "ai_tools",
		Depth:       2,
		Decision:    "approve",
		Rule:        "require_approval",
		Message:     "Network access requires approval",
		IsAgent:     false,
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := printSimulationHuman(cmd, result)
	if err != nil {
		t.Fatalf("printSimulationHuman() error = %v", err)
	}

	output := buf.String()
	wantStrings := []string{
		"Taint Simulation Result",
		"Ancestry Chain:",
		"cursor [agent] (SOURCE)",
		"bash [shell]",
		"npm [build_tool]",
		"Command:    curl https://example.com",
		"Context:    ai_tools",
		"Depth:      2",
		"APPROVE",
		"Rule:       require_approval",
		"Message:    Network access requires approval",
	}

	for _, want := range wantStrings {
		if !bytes.Contains([]byte(output), []byte(want)) {
			t.Errorf("output missing %q\ngot:\n%s", want, output)
		}
	}
}

func TestPrintSimulationHuman_Decisions(t *testing.T) {
	tests := []struct {
		decision string
		wantIcon string
	}{
		{"allow", "ALLOW"},
		{"deny", "DENY"},
		{"approve", "APPROVE"},
	}

	for _, tt := range tests {
		t.Run(tt.decision, func(t *testing.T) {
			result := &SimulationResult{
				Ancestry:   []string{"cursor"},
				ViaClasses: []string{"agent"},
				Decision:   tt.decision,
			}

			var buf bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&buf)

			err := printSimulationHuman(cmd, result)
			if err != nil {
				t.Fatalf("printSimulationHuman() error = %v", err)
			}

			output := buf.String()
			if !bytes.Contains([]byte(output), []byte(tt.wantIcon)) {
				t.Errorf("expected %q in output\ngot:\n%s", tt.wantIcon, output)
			}
		})
	}
}

func TestGuessContextName(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"Cursor", "ai_tools"},
		{"cursor", "ai_tools"},
		{"claude-desktop", "ai_tools"},
		{"Claude", "ai_tools"},
		{"code", "ai_tools"},
		{"Code", "ai_tools"},
		{"vscode", "ai_tools"},
		{"aider", "ai_tools"},
		{"Aider", "ai_tools"},
		{"unknown", "ai_tools"}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			got := guessContextName(tt.source)
			if got != tt.want {
				t.Errorf("guessContextName(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestCreateTestPolicy(t *testing.T) {
	p := createTestPolicy("ai_tools")

	if p.Name != "test-policy" {
		t.Errorf("expected policy name 'test-policy', got %q", p.Name)
	}

	if p.Version != 1 {
		t.Errorf("expected policy version 1, got %d", p.Version)
	}

	ctx, ok := p.ProcessContexts["ai_tools"]
	if !ok {
		t.Fatal("expected process context 'ai_tools' to exist")
	}

	if ctx.DefaultDecision != "deny" {
		t.Errorf("expected default decision 'deny', got %q", ctx.DefaultDecision)
	}

	if len(ctx.ChainRules) == 0 {
		t.Error("expected chain rules to be defined")
	}

	// Check that shell_laundering rule exists
	found := false
	for _, rule := range ctx.ChainRules {
		if rule.Name == "shell_laundering" {
			found = true
			if rule.Action != "deny" {
				t.Errorf("shell_laundering rule should deny, got %q", rule.Action)
			}
		}
	}
	if !found {
		t.Error("expected shell_laundering chain rule")
	}
}

func TestIntPtr(t *testing.T) {
	p := intPtr(42)
	if p == nil {
		t.Fatal("intPtr returned nil")
	}
	if *p != 42 {
		t.Errorf("intPtr(42) = %d, want 42", *p)
	}
}
