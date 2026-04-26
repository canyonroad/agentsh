package watchtower

// Same-package test so we can call the unexported validate() method
// directly without going through watchtower.New.

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/ocsf"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// minimalValidOpts returns an Options that satisfies validate() so that
// individual tests can swap a single field to exercise a specific path.
func minimalValidOpts(t *testing.T) Options {
	t.Helper()
	return Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		BatchMaxRecords: 256,
		BatchMaxBytes:   256 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer: transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
			return nil, errors.New("nopDialer: no conn")
		}),
	}
}

func TestValidate_AcceptsOCSFMapper(t *testing.T) {
	opts := minimalValidOpts(t)
	opts.Mapper = ocsf.New()
	opts.AllowStubMapper = false
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		t.Fatalf("validate() with ocsf.New() = %v, want nil", err)
	}
}

func TestValidate_RejectsStubMapperInProduction(t *testing.T) {
	opts := minimalValidOpts(t)
	opts.Mapper = compact.StubMapper{}
	opts.AllowStubMapper = false
	opts.applyDefaults()
	if err := opts.validate(); err == nil {
		t.Fatal("validate() with StubMapper accepted; expected rejection")
	}
}
