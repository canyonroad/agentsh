package api

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agentsh/agentsh/pkg/ptygrpc"
)

type ptyGRPCServer struct {
	app *App
	ptygrpc.UnimplementedAgentshPTYServer
}

func (s *ptyGRPCServer) ExecPTY(ptygrpc.AgentshPTY_ExecPTYServer) error {
	if s == nil || s.app == nil {
		// Keep the error stable so tests can detect registration without needing full app wiring.
		return status.Error(codes.Unimplemented, "pty not implemented")
	}
	return status.Error(codes.Unimplemented, "pty not implemented")
}

