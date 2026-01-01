package xpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// PolicyHandler handles policy queries from the XPC bridge.
type PolicyHandler interface {
	CheckFile(path, op string) (allow bool, rule string)
	CheckNetwork(ip string, port int, domain string) (allow bool, rule string)
	CheckCommand(cmd string, args []string) (allow bool, rule string)
	ResolveSession(pid int32) (sessionID string)
}

// Server listens on a Unix socket for policy queries.
type Server struct {
	sockPath string
	handler  PolicyHandler
	listener net.Listener
	mu       sync.Mutex
	wg       sync.WaitGroup
	ready    chan struct{} // closed when server is listening
}

// NewServer creates a new policy socket server.
func NewServer(sockPath string, handler PolicyHandler) *Server {
	if handler == nil {
		panic("xpc: handler must not be nil")
	}
	return &Server{
		sockPath: sockPath,
		handler:  handler,
		ready:    make(chan struct{}),
	}
}

// Ready returns a channel that is closed when the server is listening.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// Run starts the server and blocks until context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Remove existing socket
	os.Remove(s.sockPath)

	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Set socket permissions (readable only by root)
	if err := os.Chmod(s.sockPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	// Signal that the server is ready
	close(s.ready)

	// Start cleanup goroutine only after all setup is complete
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if s.listener != nil {
			s.listener.Close()
		}
		s.mu.Unlock()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				// Wait for active connections to finish
				s.wg.Wait()
				return nil
			default:
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var req PolicyRequest
		if err := decoder.Decode(&req); err != nil {
			return // Connection closed or error
		}

		resp := s.handleRequest(&req)
		if err := encoder.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) handleRequest(req *PolicyRequest) PolicyResponse {
	switch req.Type {
	case RequestTypeFile:
		allow, rule := s.handler.CheckFile(req.Path, req.Operation)
		return PolicyResponse{Allow: allow, Rule: rule}

	case RequestTypeNetwork:
		allow, rule := s.handler.CheckNetwork(req.IP, req.Port, req.Domain)
		return PolicyResponse{Allow: allow, Rule: rule}

	case RequestTypeCommand:
		allow, rule := s.handler.CheckCommand(req.Path, req.Args)
		return PolicyResponse{Allow: allow, Rule: rule}

	case RequestTypeSession:
		sessionID := s.handler.ResolveSession(req.PID)
		return PolicyResponse{Allow: sessionID != "", SessionID: sessionID}

	case RequestTypeEvent:
		// Events are fire-and-forget, always acknowledge
		return PolicyResponse{Allow: true}

	default:
		return PolicyResponse{Allow: false, Message: "unknown request type"}
	}
}
