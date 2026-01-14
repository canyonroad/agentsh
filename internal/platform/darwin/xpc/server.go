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

// PNACLHandler handles PNACL-specific policy queries.
// Implementations should use the pnacl package for policy evaluation.
type PNACLHandler interface {
	// CheckNetwork evaluates a network connection against PNACL rules.
	// Returns decision (allow, deny, approve, audit, etc.) and rule ID.
	CheckNetwork(req PNACLCheckRequest) (decision, ruleID string)

	// ReportEvent logs a PNACL network event.
	ReportEvent(req PNACLEventRequest)

	// GetPendingApprovals returns connections awaiting user approval.
	GetPendingApprovals() []ApprovalResponse

	// SubmitApproval records a user's approval decision.
	SubmitApproval(requestID, decision string, permanent bool) bool

	// Configure updates PNACL blocking behavior.
	Configure(blockingEnabled bool, decisionTimeout float64, failOpen bool) bool
}

// PNACLCheckRequest contains all fields for a PNACL network check.
type PNACLCheckRequest struct {
	IP             string
	Port           int
	Protocol       string
	Domain         string
	PID            int32
	BundleID       string
	ExecutablePath string
	ProcessName    string
	ParentPID      int32
}

// PNACLEventRequest contains fields for a PNACL event report.
type PNACLEventRequest struct {
	EventType string
	IP        string
	Port      int
	Protocol  string
	Domain    string
	PID       int32
	BundleID  string
	Decision  string
	RuleID    string
}

// Server listens on a Unix socket for policy queries.
type Server struct {
	sockPath     string
	handler      PolicyHandler
	pnaclHandler PNACLHandler
	listener     net.Listener
	mu           sync.Mutex
	wg           sync.WaitGroup
	ready        chan struct{} // closed when server is listening
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

// SetPNACLHandler sets the handler for PNACL requests.
// If not set, PNACL requests will return error responses.
func (s *Server) SetPNACLHandler(h PNACLHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pnaclHandler = h
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

	// Set socket permissions to allow user-space access.
	// The ApprovalDialog.app runs as user and needs to connect to fetch/submit approvals.
	// Security note: The socket is only accessible locally (Unix domain socket).
	// TODO: Consider a separate approval-only socket with restricted operations,
	// or route approval operations through the XPC service for better isolation.
	if err := os.Chmod(s.sockPath, 0666); err != nil {
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

	// PNACL request types
	case RequestTypePNACLCheck:
		return s.handlePNACLCheck(req)

	case RequestTypePNACLEvent:
		return s.handlePNACLEvent(req)

	case RequestTypePNACLGetApprovals:
		return s.handlePNACLGetApprovals()

	case RequestTypePNACLSubmit:
		return s.handlePNACLSubmit(req)

	case RequestTypePNACLConfigure:
		return s.handlePNACLConfigure(req)

	default:
		return PolicyResponse{Allow: false, Message: "unknown request type"}
	}
}

// PNACL request handlers

func (s *Server) getPNACLHandler() PNACLHandler {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pnaclHandler
}

func (s *Server) handlePNACLCheck(req *PolicyRequest) PolicyResponse {
	h := s.getPNACLHandler()
	if h == nil {
		return PolicyResponse{Allow: true, Decision: "allow", Message: "PNACL handler not configured"}
	}

	// Validate port range
	if req.Port < 0 || req.Port > 65535 {
		return PolicyResponse{Allow: false, Decision: "deny", Message: "invalid port"}
	}

	checkReq := PNACLCheckRequest{
		IP:             req.IP,
		Port:           req.Port,
		Protocol:       req.Protocol,
		Domain:         req.Domain,
		PID:            req.PID,
		BundleID:       req.BundleID,
		ExecutablePath: req.ExecutablePath,
		ProcessName:    req.ProcessName,
		ParentPID:      req.ParentPID,
	}

	decision, ruleID := h.CheckNetwork(checkReq)
	return PolicyResponse{
		Allow:    isAllowingDecision(decision),
		Decision: decision,
		RuleID:   ruleID,
	}
}

// isAllowingDecision returns true for decisions that should allow the connection.
func isAllowingDecision(decision string) bool {
	switch decision {
	case "allow", "audit", "allow_once_then_approve":
		return true
	default:
		return false
	}
}

func (s *Server) handlePNACLEvent(req *PolicyRequest) PolicyResponse {
	h := s.getPNACLHandler()
	if h == nil {
		return PolicyResponse{Allow: true, Success: true}
	}

	eventReq := PNACLEventRequest{
		EventType: req.EventType,
		IP:        req.IP,
		Port:      req.Port,
		Protocol:  req.Protocol,
		Domain:    req.Domain,
		PID:       req.PID,
		BundleID:  req.BundleID,
		Decision:  req.Decision,
		RuleID:    req.RuleID,
	}

	h.ReportEvent(eventReq)
	return PolicyResponse{Allow: true, Success: true}
}

func (s *Server) handlePNACLGetApprovals() PolicyResponse {
	h := s.getPNACLHandler()
	if h == nil {
		return PolicyResponse{Approvals: nil, Success: true}
	}

	approvals := h.GetPendingApprovals()
	return PolicyResponse{Approvals: approvals, Success: true}
}

func (s *Server) handlePNACLSubmit(req *PolicyRequest) PolicyResponse {
	h := s.getPNACLHandler()
	if h == nil {
		return PolicyResponse{Success: false, Message: "PNACL handler not configured"}
	}

	success := h.SubmitApproval(req.RequestID, req.Decision, req.Permanent)
	return PolicyResponse{Success: success}
}

func (s *Server) handlePNACLConfigure(req *PolicyRequest) PolicyResponse {
	h := s.getPNACLHandler()
	if h == nil {
		return PolicyResponse{Success: false, Message: "PNACL handler not configured"}
	}

	success := h.Configure(req.BlockingEnabled, req.DecisionTimeout, req.FailOpen)
	return PolicyResponse{Success: success}
}
