package netmonitor

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

type Proxy struct {
	sessionID string
	sess      *session.Session
	policy    *policy.Engine
	approvals *approvals.Manager
	emit      Emitter

	ln   net.Listener
	wg   sync.WaitGroup
	done chan struct{}
}

func StartProxy(listenAddr string, sessionID string, sess *session.Session, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter) (*Proxy, string, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, "", err
	}

	p := &Proxy{
		sessionID: sessionID,
		sess:      sess,
		policy:    engine,
		approvals: approvalsMgr,
		emit:      emit,
		ln:        ln,
		done:      make(chan struct{}),
	}

	p.wg.Add(1)
	go p.acceptLoop()

	u := url.URL{Scheme: "http", Host: ln.Addr().String()}
	return p, u.String(), nil
}

func (p *Proxy) Close() error {
	close(p.done)
	err := p.ln.Close()
	p.wg.Wait()
	return err
}

func (p *Proxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
				continue
			}
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			_ = p.handleConn(conn)
		}()
	}
}

func (p *Proxy) handleConn(c net.Conn) error {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	if strings.EqualFold(req.Method, http.MethodConnect) {
		return p.handleConnect(c, req)
	}
	return p.handleHTTP(c, req)
}

func (p *Proxy) handleConnect(client net.Conn, req *http.Request) error {
	hostPort := req.Host
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		portStr = "443"
	}
	port := mustAtoi(portStr, 443)

	commandID := ""
	if p.sess != nil {
		commandID = p.sess.CurrentCommandID()
	}

	dec := p.checkNetwork(host, port)
	dec = p.maybeApprove(context.Background(), commandID, dec, "network", hostPort)
	connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, dec, map[string]any{"method": "CONNECT"})
	if dec.EffectiveDecision == types.DecisionDeny {
		_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
		_ = p.emit.AppendEvent(context.Background(), connectEv)
		p.emit.Publish(connectEv)
		return nil
	}
	_ = p.emit.AppendEvent(context.Background(), connectEv)
	p.emit.Publish(connectEv)

	up, err := net.DialTimeout("tcp", hostPort, 20*time.Second)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return nil
	}
	defer up.Close()

	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")

	var upBytes, downBytes int64
	errCh := make(chan error, 2)
	go func() {
		n, e := io.Copy(up, client)
		upBytes = n
		errCh <- e
	}()
	go func() {
		n, e := io.Copy(client, up)
		downBytes = n
		errCh <- e
	}()
	<-errCh
	<-errCh

	closeEv := p.emitNetEvent(context.Background(), "net_close", commandID, host, hostPort, port, dec, map[string]any{"bytes_sent": upBytes, "bytes_received": downBytes})
	_ = p.emit.AppendEvent(context.Background(), closeEv)
	p.emit.Publish(closeEv)
	return nil
}

func (p *Proxy) handleHTTP(client net.Conn, req *http.Request) error {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}
	port := 80
	if req.URL.Scheme == "https" {
		port = 443
	}

	commandID := ""
	if p.sess != nil {
		commandID = p.sess.CurrentCommandID()
	}

	dec := p.checkNetwork(host, port)
	dec = p.maybeApprove(context.Background(), commandID, dec, "network", host)
	connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, host, port, dec, map[string]any{"method": req.Method})
	if dec.EffectiveDecision == types.DecisionDeny {
		resp := "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nblocked by policy\n"
		_, _ = io.WriteString(client, resp)
		_ = p.emit.AppendEvent(context.Background(), connectEv)
		p.emit.Publish(connectEv)
		return nil
	}
	_ = p.emit.AppendEvent(context.Background(), connectEv)
	p.emit.Publish(connectEv)

	transport := &http.Transport{
		Proxy: nil,
	}

	req.RequestURI = ""
	req.URL.Scheme = "http"
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return nil
	}
	defer resp.Body.Close()

	if err := resp.Write(client); err != nil {
		return nil
	}
	return nil
}

func (p *Proxy) checkNetwork(domain string, port int) policy.Decision {
	if p.policy == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	return p.policy.CheckNetwork(domain, port)
}

func (p *Proxy) maybeApprove(ctx context.Context, commandID string, dec policy.Decision, kind string, target string) policy.Decision {
	if dec.PolicyDecision != types.DecisionApprove || dec.EffectiveDecision != types.DecisionApprove {
		return dec
	}
	if p.approvals == nil {
		return dec
	}
	req := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: p.sessionID,
		CommandID: commandID,
		Kind:      kind,
		Target:    target,
		Rule:      dec.Rule,
		Message:   dec.Message,
	}
	res, err := p.approvals.RequestApproval(ctx, req)
	if dec.Approval != nil {
		dec.Approval.ID = req.ID
	}
	if err != nil || !res.Approved {
		dec.EffectiveDecision = types.DecisionDeny
	} else {
		dec.EffectiveDecision = types.DecisionAllow
	}
	return dec
}

func (p *Proxy) emitNetEvent(ctx context.Context, evType string, commandID string, domain string, remote string, port int, dec policy.Decision, fields map[string]any) types.Event {
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: p.sessionID,
		CommandID: commandID,
		Domain:    strings.ToLower(domain),
		Remote:    remote,
		Fields:    fields,
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
			Approval:          dec.Approval,
		},
	}
	return ev
}

func mustAtoi(s string, def int) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	if n == 0 {
		return def
	}
	return n
}
