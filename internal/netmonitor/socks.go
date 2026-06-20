package netmonitor

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
