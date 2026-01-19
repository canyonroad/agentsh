package ancestry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentDetector_EnvMarkers(t *testing.T) {
	cfg := DefaultAgentDetectorConfig()
	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	tests := []struct {
		name      string
		env       map[string]string
		wantAgent bool
		wantSig   DetectionSignal
	}{
		{
			name: "claude agent env",
			env: map[string]string{
				"CLAUDE_AGENT": "true",
			},
			wantAgent: true,
			wantSig:   SignalEnvMarker,
		},
		{
			name: "copilot agent mode env",
			env: map[string]string{
				"COPILOT_AGENT_MODE": "enabled",
			},
			wantAgent: true,
			wantSig:   SignalEnvMarker,
		},
		{
			name: "aider env prefix",
			env: map[string]string{
				"AIDER_MODEL": "gpt-4",
			},
			wantAgent: true,
			wantSig:   SignalEnvMarker,
		},
		{
			name: "ai agent env",
			env: map[string]string{
				"AI_AGENT": "1",
			},
			wantAgent: true,
			wantSig:   SignalEnvMarker,
		},
		{
			name: "normal env - no agent",
			env: map[string]string{
				"HOME":   "/home/user",
				"PATH":   "/usr/bin",
				"EDITOR": "vim",
			},
			wantAgent: false,
		},
		{
			name:      "empty env",
			env:       nil,
			wantAgent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &DetectContext{
				PID:  1000,
				Comm: "bash",
				Env:  tt.env,
			}

			result := detector.Detect(ctx)
			assert.Equal(t, tt.wantAgent, result.IsAgent)
			if tt.wantAgent {
				assert.Contains(t, result.Signals, tt.wantSig)
				assert.Greater(t, result.Confidence, 0.5)
			}
		})
	}
}

func TestAgentDetector_ArgPatterns(t *testing.T) {
	cfg := DefaultAgentDetectorConfig()
	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	tests := []struct {
		name      string
		args      []string
		wantAgent bool
	}{
		{
			name:      "agent-mode flag",
			args:      []string{"node", "index.js", "--agent-mode"},
			wantAgent: true,
		},
		{
			name:      "agent flag",
			args:      []string{"python", "main.py", "--agent"},
			wantAgent: true,
		},
		{
			name:      "autonomous flag",
			args:      []string{"./cli", "--autonomous", "task"},
			wantAgent: true,
		},
		{
			name:      "run-agent command",
			args:      []string{"run-agent", "task"},
			wantAgent: true,
		},
		{
			name:      "normal args - no agent",
			args:      []string{"node", "index.js", "--port", "8080"},
			wantAgent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &DetectContext{
				PID:  1000,
				Comm: "node",
				Args: tt.args,
			}

			result := detector.Detect(ctx)
			assert.Equal(t, tt.wantAgent, result.IsAgent)
			if tt.wantAgent {
				assert.Contains(t, result.Signals, SignalArgPattern)
			}
		})
	}
}

func TestAgentDetector_ProcessPatterns(t *testing.T) {
	cfg := DefaultAgentDetectorConfig()
	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	tests := []struct {
		name      string
		comm      string
		exePath   string
		wantAgent bool
	}{
		{
			name:      "claude-agent process",
			comm:      "claude-agent",
			wantAgent: true,
		},
		{
			name:      "copilot-agent process",
			comm:      "copilot-agent",
			wantAgent: true,
		},
		{
			name:      "aider process",
			comm:      "aider",
			wantAgent: true,
		},
		{
			name:      "my-agent suffix",
			comm:      "my-agent",
			wantAgent: true,
		},
		{
			name:      "task_agent suffix",
			comm:      "task_agent",
			wantAgent: true,
		},
		{
			name:      "normal process - no agent",
			comm:      "node",
			wantAgent: false,
		},
		{
			name:      "bash - no agent",
			comm:      "bash",
			wantAgent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &DetectContext{
				PID:     1000,
				Comm:    tt.comm,
				ExePath: tt.exePath,
			}

			result := detector.Detect(ctx)
			assert.Equal(t, tt.wantAgent, result.IsAgent)
			if tt.wantAgent {
				assert.Contains(t, result.Signals, SignalProcessPattern)
			}
		})
	}
}

func TestAgentDetector_SelfRegistration(t *testing.T) {
	cfg := DefaultAgentDetectorConfig()
	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	t.Run("via env var", func(t *testing.T) {
		ctx := &DetectContext{
			PID:  1000,
			Comm: "my-custom-process",
			Env: map[string]string{
				"AGENTSH_AGENT_ID": "my-agent-123",
			},
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.Contains(t, result.Signals, SignalSelfRegistered)
		assert.Equal(t, "my-agent-123", result.Details["self_registered"])
		assert.Equal(t, 1.0, result.Confidence) // 100% confidence for self-registration
	})

	t.Run("via registry", func(t *testing.T) {
		detector.Registry().Register(2000, "registered-agent", "api")

		ctx := &DetectContext{
			PID:  2000,
			Comm: "unknown-process",
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.Contains(t, result.Signals, SignalSelfRegistered)
	})
}

func TestAgentDetector_UserDeclared(t *testing.T) {
	cfg := DefaultAgentDetectorConfig()
	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	t.Run("matches comm", func(t *testing.T) {
		ctx := &DetectContext{
			PID:         1000,
			Comm:        "my-custom-ai",
			UserMarkers: []string{"my-custom-ai", "another-agent"},
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.Contains(t, result.Signals, SignalUserDeclared)
		assert.Equal(t, 1.0, result.Confidence)
	})

	t.Run("matches exe path", func(t *testing.T) {
		ctx := &DetectContext{
			PID:         1000,
			Comm:        "python",
			ExePath:     "/usr/bin/my-agent",
			UserMarkers: []string{"my-agent"},
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.Contains(t, result.Signals, SignalUserDeclared)
	})

	t.Run("no match", func(t *testing.T) {
		ctx := &DetectContext{
			PID:         1000,
			Comm:        "bash",
			ExePath:     "/bin/bash",
			UserMarkers: []string{"my-agent"},
		}

		result := detector.Detect(ctx)
		assert.False(t, result.IsAgent)
	})
}

func TestAgentDetector_ConfidenceScoring(t *testing.T) {
	cfg := DefaultAgentDetectorConfig()
	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	t.Run("single signal - env marker", func(t *testing.T) {
		ctx := &DetectContext{
			PID:  1000,
			Comm: "bash",
			Env:  map[string]string{"CLAUDE_AGENT": "1"},
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.InDelta(t, 0.9, result.Confidence, 0.01)
	})

	t.Run("multiple signals - higher confidence", func(t *testing.T) {
		ctx := &DetectContext{
			PID:  1000,
			Comm: "claude-agent",
			Args: []string{"./run", "--agent-mode"},
			Env:  map[string]string{"AI_AGENT": "1"},
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		// Multiple signals should give higher confidence
		assert.Greater(t, result.Confidence, 0.9)
	})

	t.Run("no signals - zero confidence", func(t *testing.T) {
		ctx := &DetectContext{
			PID:  1000,
			Comm: "bash",
		}

		result := detector.Detect(ctx)
		assert.False(t, result.IsAgent)
		assert.Equal(t, 0.0, result.Confidence)
	})
}

func TestAgentDetector_CustomSignatures(t *testing.T) {
	cfg := AgentDetectorConfig{
		Signatures: AgentSignatures{
			EnvMarkers:      []string{"MY_AGENT_*"},
			ArgPatterns:     []string{"--my-agent-mode"},
			ProcessPatterns: []string{"myagent*"},
		},
		ConfidenceThreshold: 0.5,
	}

	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	t.Run("custom env marker", func(t *testing.T) {
		ctx := &DetectContext{
			PID:  1000,
			Comm: "node",
			Env:  map[string]string{"MY_AGENT_ID": "123"},
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.Contains(t, result.Signals, SignalEnvMarker)
	})

	t.Run("custom arg pattern", func(t *testing.T) {
		ctx := &DetectContext{
			PID:  1000,
			Comm: "node",
			Args: []string{"node", "--my-agent-mode"},
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.Contains(t, result.Signals, SignalArgPattern)
	})

	t.Run("custom process pattern", func(t *testing.T) {
		ctx := &DetectContext{
			PID:  1000,
			Comm: "myagent-v2",
		}

		result := detector.Detect(ctx)
		assert.True(t, result.IsAgent)
		assert.Contains(t, result.Signals, SignalProcessPattern)
	})
}

func TestAgentRegistry(t *testing.T) {
	registry := NewAgentRegistry()

	t.Run("register and check", func(t *testing.T) {
		registry.Register(1000, "agent-1", "api")
		assert.True(t, registry.IsRegistered(1000))
		assert.False(t, registry.IsRegistered(1001))
	})

	t.Run("get info", func(t *testing.T) {
		registry.Register(2000, "agent-2", "env")

		info, ok := registry.GetInfo(2000)
		assert.True(t, ok)
		assert.Equal(t, "agent-2", info.AgentID)
		assert.Equal(t, "env", info.Method)
		assert.False(t, info.RegisteredAt.IsZero())
	})

	t.Run("unregister", func(t *testing.T) {
		registry.Register(3000, "agent-3", "file")
		assert.True(t, registry.IsRegistered(3000))

		registry.Unregister(3000)
		assert.False(t, registry.IsRegistered(3000))
	})
}

func TestBehaviorDetector(t *testing.T) {
	t.Run("high exec rate", func(t *testing.T) {
		detector := NewBehaviorDetector(BehaviorDetectorConfig{
			Window: time.Minute,
		})

		// Simulate 15 execs in the window (>10/min threshold)
		for i := 0; i < 15; i++ {
			detector.RecordExec(1000)
		}

		score := detector.GetScore(1000)
		assert.InDelta(t, 0.3, score, 0.01) // High exec rate contributes 0.3
	})

	t.Run("llm api access", func(t *testing.T) {
		detector := NewBehaviorDetector(BehaviorDetectorConfig{
			Window: time.Minute,
		})

		detector.RecordNetworkAccess(1000, "api.anthropic.com")

		score := detector.GetScore(1000)
		assert.InDelta(t, 0.5, score, 0.01) // LLM API access contributes 0.5
	})

	t.Run("combined signals", func(t *testing.T) {
		detector := NewBehaviorDetector(BehaviorDetectorConfig{
			Window: time.Minute,
		})

		// High exec rate
		for i := 0; i < 15; i++ {
			detector.RecordExec(1000)
		}
		// LLM API access
		detector.RecordNetworkAccess(1000, "api.openai.com")

		score := detector.GetScore(1000)
		assert.InDelta(t, 0.8, score, 0.01) // 0.3 + 0.5
	})

	t.Run("clear removes events", func(t *testing.T) {
		detector := NewBehaviorDetector(BehaviorDetectorConfig{
			Window: time.Minute,
		})

		detector.RecordExec(1000)
		detector.RecordNetworkAccess(1000, "api.anthropic.com")
		assert.Greater(t, detector.GetScore(1000), 0.0)

		detector.Clear(1000)
		assert.Equal(t, 0.0, detector.GetScore(1000))
	})

	t.Run("no activity", func(t *testing.T) {
		detector := NewBehaviorDetector(BehaviorDetectorConfig{
			Window: time.Minute,
		})

		score := detector.GetScore(9999) // Unknown PID
		assert.Equal(t, 0.0, score)
	})
}

func TestAgentDetector_WithBehavioral(t *testing.T) {
	cfg := AgentDetectorConfig{
		Signatures:          AgentSignatures{}, // No signatures
		ConfidenceThreshold: 0.5,
		EnableBehavioral:    true,
		BehavioralWindow:    time.Minute,
	}

	detector, err := NewAgentDetector(cfg)
	require.NoError(t, err)

	// Simulate behavioral signals
	for i := 0; i < 15; i++ {
		detector.RecordExec(1000)
	}
	detector.RecordNetworkAccess(1000, "api.anthropic.com")

	ctx := &DetectContext{
		PID:  1000,
		Comm: "unknown-process",
	}

	result := detector.Detect(ctx)
	assert.True(t, result.IsAgent)
	assert.Contains(t, result.Signals, SignalBehavioral)
	assert.Greater(t, result.Confidence, 0.5)
}

func TestDefaultAgentSignatures(t *testing.T) {
	sigs := DefaultAgentSignatures()

	assert.NotEmpty(t, sigs.EnvMarkers)
	assert.NotEmpty(t, sigs.ArgPatterns)
	assert.NotEmpty(t, sigs.ProcessPatterns)

	// Verify expected patterns are present
	assert.Contains(t, sigs.EnvMarkers, "CLAUDE_AGENT=*")
	assert.Contains(t, sigs.ArgPatterns, "--agent-mode")
	assert.Contains(t, sigs.ProcessPatterns, "aider")
}

func TestSignalConfidence(t *testing.T) {
	// Verify confidence levels are set correctly
	assert.Equal(t, 1.0, SignalConfidence[SignalUserDeclared])
	assert.Equal(t, 1.0, SignalConfidence[SignalSelfRegistered])
	assert.Equal(t, 0.9, SignalConfidence[SignalEnvMarker])
	assert.Equal(t, 0.9, SignalConfidence[SignalArgPattern])
	assert.Equal(t, 0.8, SignalConfidence[SignalProcessPattern])
	assert.Equal(t, 0.6, SignalConfidence[SignalBehavioral])
}
