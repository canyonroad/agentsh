package cli

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

// mockCLIClient implements the CLIClient interface for testing.
type mockCLIClient struct {
	session     types.Session
	proxyStatus map[string]any
}

func (m *mockCLIClient) CreateSession(ctx context.Context, workspace, policy string) (types.Session, error) {
	return m.session, nil
}
func (m *mockCLIClient) CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error) {
	return m.session, nil
}
func (m *mockCLIClient) CreateSessionWithRequest(ctx context.Context, req types.CreateSessionRequest) (types.Session, error) {
	return m.session, nil
}
func (m *mockCLIClient) ListSessions(ctx context.Context) ([]types.Session, error) {
	return []types.Session{m.session}, nil
}
func (m *mockCLIClient) GetSession(ctx context.Context, id string) (types.Session, error) {
	return m.session, nil
}
func (m *mockCLIClient) DestroySession(ctx context.Context, id string) error { return nil }
func (m *mockCLIClient) PatchSession(ctx context.Context, id string, req types.SessionPatchRequest) (types.Session, error) {
	return m.session, nil
}
func (m *mockCLIClient) Exec(ctx context.Context, sessionID string, req types.ExecRequest) (types.ExecResponse, error) {
	return types.ExecResponse{}, nil
}
func (m *mockCLIClient) ExecStream(ctx context.Context, sessionID string, req types.ExecRequest) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockCLIClient) KillCommand(ctx context.Context, sessionID string, commandID string) error {
	return nil
}
func (m *mockCLIClient) QuerySessionEvents(ctx context.Context, sessionID string, q url.Values) ([]types.Event, error) {
	return nil, nil
}
func (m *mockCLIClient) SearchEvents(ctx context.Context, q url.Values) ([]types.Event, error) {
	return nil, nil
}
func (m *mockCLIClient) StreamSessionEvents(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockCLIClient) OutputChunk(ctx context.Context, sessionID, commandID string, stream string, offset, limit int64) (map[string]any, error) {
	return nil, nil
}
func (m *mockCLIClient) ListApprovals(ctx context.Context) ([]map[string]any, error) { return nil, nil }
func (m *mockCLIClient) ResolveApproval(ctx context.Context, id string, decision string, reason string) error {
	return nil
}
func (m *mockCLIClient) PolicyTest(ctx context.Context, sessionID, operation, path string) (map[string]any, error) {
	return nil, nil
}
func (m *mockCLIClient) GetProxyStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	return m.proxyStatus, nil
}

func TestPrintSessionCreated(t *testing.T) {
	tests := []struct {
		name        string
		session     types.Session
		proxyStatus map[string]any
		wantStrings []string
	}{
		{
			name: "with proxy and DLP patterns",
			session: types.Session{
				ID:        "test-session-123",
				State:     types.SessionStateReady,
				CreatedAt: time.Now(),
				ProxyURL:  "http://127.0.0.1:52341",
			},
			proxyStatus: map[string]any{
				"state":           "running",
				"address":         "127.0.0.1:52341",
				"dlp_mode":        "redact",
				"active_patterns": float64(5),
				"pattern_names":   []any{"email", "phone", "credit_card", "ssn", "api_key"},
			},
			wantStrings: []string{
				"Session test-session-123 started",
				"Proxy: http://127.0.0.1:52341",
				"DLP: redact (email, phone, credit_card, ssn, api_key)",
				"Export for agent:",
				"export ANTHROPIC_BASE_URL=http://127.0.0.1:52341",
				"export OPENAI_BASE_URL=http://127.0.0.1:52341",
			},
		},
		{
			name: "with DLP disabled",
			session: types.Session{
				ID:        "session-no-dlp",
				State:     types.SessionStateReady,
				CreatedAt: time.Now(),
				ProxyURL:  "http://127.0.0.1:12345",
			},
			proxyStatus: map[string]any{
				"state":    "running",
				"address":  "127.0.0.1:12345",
				"dlp_mode": "disabled",
			},
			wantStrings: []string{
				"Session session-no-dlp started",
				"Proxy: http://127.0.0.1:12345",
				"Export for agent:",
			},
		},
		{
			name: "fallback to session proxy URL",
			session: types.Session{
				ID:       "session-fallback",
				ProxyURL: "http://127.0.0.1:99999",
			},
			proxyStatus: nil,
			wantStrings: []string{
				"Session session-fallback started",
				"Proxy: http://127.0.0.1:99999",
				"export ANTHROPIC_BASE_URL=http://127.0.0.1:99999",
			},
		},
		{
			name: "DLP with pattern count fallback",
			session: types.Session{
				ID: "session-count-fallback",
			},
			proxyStatus: map[string]any{
				"state":           "running",
				"address":         "127.0.0.1:18080",
				"dlp_mode":        "redact",
				"active_patterns": float64(3),
				// No pattern_names provided
			},
			wantStrings: []string{
				"Session session-count-fallback started",
				"DLP: redact (3 patterns active)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockCLIClient{
				session:     tt.session,
				proxyStatus: tt.proxyStatus,
			}

			var buf bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&buf)

			err := printSessionCreated(cmd, client, tt.session)
			if err != nil {
				t.Fatalf("printSessionCreated() error = %v", err)
			}

			output := buf.String()
			for _, want := range tt.wantStrings {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestGetFloatVal(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]any
		key      string
		expected float64
	}{
		{"float64 value", map[string]any{"count": float64(42)}, "count", 42},
		{"int value", map[string]any{"count": int(42)}, "count", 42},
		{"missing key", map[string]any{}, "count", 0},
		{"wrong type", map[string]any{"count": "42"}, "count", 0},
		{"nil map", nil, "count", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFloatVal(tt.m, tt.key)
			if got != tt.expected {
				t.Errorf("getFloatVal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSessionCreateCmd_HasJSONFlag(t *testing.T) {
	cmd := newSessionCreateCmd()

	// Check --json flag exists
	jsonFlag := cmd.Flags().Lookup("json")
	if jsonFlag == nil {
		t.Error("expected --json flag on session create command")
	}
}
