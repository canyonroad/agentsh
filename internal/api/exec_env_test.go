package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
)

func TestMergeEnv_MarksInSession(t *testing.T) {
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	out := mergeEnv(nil, sess, nil)
	got := map[string]string{}
	for _, kv := range out {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				got[kv[:i]] = kv[i+1:]
				break
			}
		}
	}

	if got["AGENTSH_IN_SESSION"] != "1" {
		t.Fatalf("expected AGENTSH_IN_SESSION=1, got %q", got["AGENTSH_IN_SESSION"])
	}
}

