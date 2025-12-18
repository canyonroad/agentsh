//go:build !linux
// +build !linux

package netmonitor

import (
	"errors"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

type TransparentTCP struct{}

func StartTransparentTCP(listenAddr string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter) (*TransparentTCP, int, error) {
	return nil, 0, errors.New("transparent TCP is only supported on Linux")
}

func (t *TransparentTCP) Close() error { return nil }

