package netmonitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/agentsh/agentsh/internal/tor"
)

// SOCKS5 reply codes (RFC 1928).
const (
	socksVer               = 0x05
	socksCmdConnect        = 0x01
	socksRepSuccess        = 0x00
	socksRepGeneralFailure = 0x01
	socksRepNotAllowed     = 0x02 // connection not allowed by ruleset

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// readSocksGreeting consumes the client's method-selection greeting:
// VER NMETHODS METHODS...
func readSocksGreeting(r io.Reader) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return err
	}
	if head[0] != socksVer {
		return fmt.Errorf("socks: bad version 0x%02x", head[0])
	}
	n := int(head[1])
	if n > 0 {
		if _, err := io.ReadFull(r, make([]byte, n)); err != nil {
			return err
		}
	}
	return nil
}

// writeSocksMethod replies to the greeting with the selected method.
func writeSocksMethod(w io.Writer, method byte) error {
	_, err := w.Write([]byte{socksVer, method})
	return err
}

type socksReq struct {
	atyp byte
	addr []byte // raw address bytes (domain text, or 4/16-byte IP)
	host string
	port int
}

// readSocksConnect reads a CONNECT request: VER CMD RSV ATYP ADDR PORT.
func readSocksConnect(r io.Reader) (socksReq, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return socksReq{}, err
	}
	if head[0] != socksVer {
		return socksReq{}, fmt.Errorf("socks: bad version 0x%02x", head[0])
	}
	if head[1] != socksCmdConnect {
		return socksReq{}, fmt.Errorf("socks: unsupported command 0x%02x", head[1])
	}
	var req socksReq
	req.atyp = head[3]
	switch req.atyp {
	case atypIPv4:
		req.addr = make([]byte, 4)
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = net.IP(req.addr).String()
	case atypIPv6:
		req.addr = make([]byte, 16)
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = net.IP(req.addr).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return socksReq{}, err
		}
		req.addr = make([]byte, int(lb[0]))
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = string(req.addr)
	default:
		return socksReq{}, fmt.Errorf("socks: bad atyp 0x%02x", req.atyp)
	}
	portB := make([]byte, 2)
	if _, err := io.ReadFull(r, portB); err != nil {
		return socksReq{}, err
	}
	req.port = int(binary.BigEndian.Uint16(portB))
	return req, nil
}

// encodeConnectReq re-serializes a CONNECT request for the upstream Tor SOCKS.
func encodeConnectReq(req socksReq) []byte {
	out := []byte{socksVer, socksCmdConnect, 0x00, req.atyp}
	if req.atyp == atypDomain {
		out = append(out, byte(len(req.addr)))
	}
	out = append(out, req.addr...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(req.port))
	return append(out, p[:]...)
}

// writeSocksReply writes a reply with a null IPv4 bind address.
func writeSocksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socksVer, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// TorGatewayPolicy is the subset of *tor.Policy the SOCKS front-end needs.
type TorGatewayPolicy interface {
	GatewayActive() bool
	EvalSocksTarget(host string, port int) (tor.Verdict, bool)
}

// handleTorSocks terminates a client SOCKS5 CONNECT, evaluates the target
// against the onion gateway policy, and either proxies the stream to the
// real Tor SOCKS daemon at upstreamAddr or replies "not allowed by ruleset".
// Fail-closed on any error. Emits one tor_control{vector:onion} event.
func handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string) error {
	defer conn.Close()

	if err := readSocksGreeting(conn); err != nil {
		return err
	}
	if err := writeSocksMethod(conn, 0x00); err != nil { // no-auth
		return err
	}
	req, err := readSocksConnect(conn)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}

	v, ok := pol.EvalSocksTarget(req.host, req.port)
	if ok {
		emitOnionEvent(emit, sessionID, commandID, v)
	}
	if !ok || v.Decision != "allow" {
		_ = writeSocksReply(conn, socksRepNotAllowed)
		return nil
	}

	up, err := net.DialTimeout("tcp", upstreamAddr, 20*time.Second)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	defer up.Close()

	// Act as a SOCKS5 client to the real Tor daemon for the same target.
	if _, err := up.Write([]byte{socksVer, 0x01, 0x00}); err != nil { // greeting: 1 method, no-auth
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	if _, err := io.ReadFull(up, make([]byte, 2)); err != nil { // method selection
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	if _, err := up.Write(encodeConnectReq(req)); err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	upReply, err := readSocksReply(up)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	// Relay the upstream's reply verbatim to the client.
	if _, err := conn.Write(upReply); err != nil {
		return err
	}

	splice(conn, up)
	return nil
}

// readSocksReply reads a full SOCKS5 reply (VER REP RSV ATYP ADDR PORT).
func readSocksReply(r io.Reader) ([]byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	var addrLen int
	switch head[3] {
	case atypIPv4:
		addrLen = 4
	case atypIPv6:
		addrLen = 16
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		head = append(head, lb[0])
		addrLen = int(lb[0])
	default:
		return nil, fmt.Errorf("socks: bad reply atyp 0x%02x", head[3])
	}
	rest := make([]byte, addrLen+2) // addr + port
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

func splice(a, b net.Conn) {
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(a, b); errCh <- e }()
	go func() { _, e := io.Copy(b, a); errCh <- e }()
	<-errCh
}

func emitOnionEvent(emit Emitter, sessionID, commandID string, v tor.Verdict) {
	if emit == nil {
		return
	}
	ev := tor.BuildControlEvent(sessionID, commandID, 0, v)
	_ = emit.AppendEvent(context.Background(), ev)
	emit.Publish(ev)
}
