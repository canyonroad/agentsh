package xpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// ExecHandler handles exec pipeline checks from the ESF client.
type ExecHandler interface {
	CheckExec(executable string, args []string, pid int32, parentPID int32, sessionID string) ExecCheckResult
}

// SessionRegistrar handles session lifecycle events.
// Implementations forward these to the ESF client for session-scoped filtering.
type SessionRegistrar interface {
	RegisterSession(rootPID int32, sessionID string)
	UnregisterSession(rootPID int32)
}

// ExecCheckResult contains the full exec pipeline decision.
type ExecCheckResult struct {
	Decision string // "allow", "deny", "approve", "redirect", "audit"
	Action   string // "continue", "redirect", "deny"
	Rule     string
	Message  string
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
	sockPath           string
	handler            PolicyHandler
	pnaclHandler       PNACLHandler
	execHandler        ExecHandler
	sessionRegistrar   SessionRegistrar
	listener           net.Listener
	mu                 sync.Mutex
	wg                 sync.WaitGroup
	ready              chan struct{} // closed when server startup completes (check startErr)
	startErr           error        // non-nil if Run failed during startup
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

// SetExecHandler sets the handler for exec pipeline checks.
// If not set, exec_check requests fall back to the basic command handler.
func (s *Server) SetExecHandler(h ExecHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execHandler = h
}

// SetSessionRegistrar sets the handler for session lifecycle events.
// If not set, register/unregister session requests are acknowledged but no-op.
func (s *Server) SetSessionRegistrar(r SessionRegistrar) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionRegistrar = r
}

// Ready returns a channel that is closed when server startup completes.
// After Ready() fires, check StartErr() to see if startup succeeded.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// StartErr returns a non-nil error if Run failed during startup.
// Only valid after Ready() has fired.
func (s *Server) StartErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startErr
}

// Run starts the server and blocks until context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Remove existing socket
	os.Remove(s.sockPath)

	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		err = fmt.Errorf("listen: %w", err)
		s.mu.Lock()
		s.startErr = err
		s.mu.Unlock()
		close(s.ready)
		return err
	}

	// Set socket permissions to allow user-space access.
	// The ApprovalDialog.app runs as user and needs to connect to fetch/submit approvals.
	// Security note: The socket is only accessible locally (Unix domain socket).
	// TODO(security): The world-writable socket allows any local process to send
	// state-changing requests (register_session, unregister_session). Consider:
	//   1. A separate approval-only socket with restricted operations
	//   2. Routing approval operations through the XPC service for better isolation
	//   3. Using SO_PEERCRED/getpeereid to authenticate peers for state-changing ops
	if err := os.Chmod(s.sockPath, 0666); err != nil {
		ln.Close()
		err = fmt.Errorf("chmod: %w", err)
		s.mu.Lock()
		s.startErr = err
		s.mu.Unlock()
		close(s.ready)
		return err
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

	case RequestTypeExecCheck:
		return s.handleExecCheck(req)

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

	// Session management request types
	case RequestTypeRegisterSession:
		return s.handleRegisterSession(req)

	case RequestTypeUnregisterSession:
		return s.handleUnregisterSession(req)

	case RequestTypeMuteProcess:
		return s.handleMuteProcess(req)

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

func (s *Server) handleExecCheck(req *PolicyRequest) PolicyResponse {
	s.mu.Lock()
	h := s.execHandler
	s.mu.Unlock()

	if h == nil {
		// No exec handler — fall back to simple allow/deny via policy handler.
		// Populate ExecDecision to keep the response contract consistent.
		allow, rule := s.handler.CheckCommand(req.Path, req.Args)
		action := "continue"
		execDecision := "allow"
		if !allow {
			action = "deny"
			execDecision = "deny"
		}
		return PolicyResponse{Allow: allow, Rule: rule, Action: action, ExecDecision: execDecision}
	}

	result := h.CheckExec(req.Path, req.Args, req.PID, req.ParentPID, req.SessionID)
	return PolicyResponse{
		Allow:        result.Action == "continue",
		Rule:         result.Rule,
		Action:       result.Action,
		ExecDecision: result.Decision,
		Message:      result.Message,
	}
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

// Session management request handlers

func (s *Server) getSessionRegistrar() SessionRegistrar {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionRegistrar
}

func (s *Server) handleRegisterSession(req *PolicyRequest) PolicyResponse {
	r := s.getSessionRegistrar()
	if r != nil {
		r.RegisterSession(req.RootPID, req.SessionID)
	}
	return PolicyResponse{Allow: true, Success: true}
}

func (s *Server) handleUnregisterSession(req *PolicyRequest) PolicyResponse {
	r := s.getSessionRegistrar()
	if r != nil {
		r.UnregisterSession(req.RootPID)
	}
	return PolicyResponse{Allow: true, Success: true}
}

func (s *Server) handleMuteProcess(req *PolicyRequest) PolicyResponse {
	// TODO(phase2): Mute process requests are currently a no-op on the Go server side.
	// The actual muting requires the ESFClient to call es_mute_process(), which can
	// only be done from the System Extension process. The muteProcess request from
	// PolicyBridge is routed here, but the Go server cannot directly invoke ES APIs.
	// To implement: extend SessionRegistrar with a MuteProcess(pid int32) method
	// that forwards to the ESFClient via the XPC service's reverse channel.
	slog.Info("xpc: mute_process request received (no-op until phase2 wiring)",
		"pid", req.PID,
	)
	return PolicyResponse{Allow: true, Success: true}
}
