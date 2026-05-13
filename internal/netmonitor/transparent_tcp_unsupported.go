//go:build !linux
// +build !linux

package netmonitor

import (
	"errors"

	"github.com/agentsh/agentsh/internal/approvals"
	dbevents "github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

type TransparentTCP struct{}

func StartTransparentTCP(listenAddr string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*TransparentTCP, int, error) {
	return nil, 0, errors.New("transparent TCP is only supported on Linux")
}

func (t *TransparentTCP) SetDBBypassEmitter(em *dbevents.BypassEmitter) {}

func (t *TransparentTCP) Close() error { return nil }
