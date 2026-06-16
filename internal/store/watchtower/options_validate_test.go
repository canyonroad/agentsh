package watchtower

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

func TestValidate_CredentialSourceAndClientCertMutuallyExclusive(t *testing.T) {
	t.Parallel()
	o := baseValidOptionsForAuthTest(t)
	o.CredentialSource = NewStaticCredentialSource("kid.secret")
	o.TLSCertFile = "/tmp/cert.pem"
	o.TLSKeyFile = "/tmp/key.pem"
	err := o.validate()
	if err == nil {
		t.Fatal("expected validate() to reject CredentialSource + client cert together")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v, want mention of mutual exclusion", err)
	}
}

func TestValidate_CredentialSourceOnlyOK(t *testing.T) {
	t.Parallel()
	o := baseValidOptionsForAuthTest(t)
	o.CredentialSource = NewStaticCredentialSource("kid.secret")
	if err := o.validate(); err != nil {
		t.Fatalf("validate() with only a credential source: %v", err)
	}
}

func baseValidOptionsForAuthTest(t *testing.T) Options {
	t.Helper()
	o := Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		AllowStubMapper: true,
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "agent-1",
		SessionID:       "sess-1",
		HMACKeyID:       "k1",
		HMACSecret:      make([]byte, audit.MinKeyLength),
	}
	o.applyDefaults()
	return o
}
