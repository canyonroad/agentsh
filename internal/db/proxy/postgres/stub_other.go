//go:build !linux

// Package postgres provides a non-Linux stub so cross-compilation
// (GOOS=windows go build ./...) stays green. The proxy is Linux-only;
// callers on other platforms get errors.ErrUnsupported when starting it.
package postgres

import (
	"context"
	"errors"
	"log/slog"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

type Service struct {
	Name     string
	Family   string
	Dialect  string
	Upstream string
	TLSMode  string
	Listen   ServiceListener
	Service  policy.DBService
}

type ServiceListener struct {
	Kind string
	Path string
	Host string
	Port int
}

type Config struct {
	Unavoidability service.Unavoidability
	Services       []Service
	StateDir       string
	Sink           events.Sink
	Logger         *slog.Logger
	Policy         *policy.RuleSet // current rule set; nil means "no rules" (implicit deny). Hot-swappable in a later plan.
}

type Server struct {
	sentinel bool
}

// New on non-Linux always succeeds and returns a sentinel that refuses to
// start unless Unavoidability == off (in which case Start is a no-op too).
func New(cfg Config) (*Server, error) {
	return &Server{sentinel: cfg.Unavoidability == service.UnavoidabilityOff}, nil
}

func (s *Server) Start(ctx context.Context) error {
	if s.sentinel {
		return nil
	}
	return errors.ErrUnsupported
}

func (s *Server) Shutdown(ctx context.Context) error { return nil }
