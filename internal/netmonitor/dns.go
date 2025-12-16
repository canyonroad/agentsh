package netmonitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type DNSInterceptor struct {
	sessionID string
	sess      *session.Session
	emit      Emitter

	pc   net.PacketConn
	wg   sync.WaitGroup
	done chan struct{}

	upstream string
}

func StartDNS(listenAddr string, upstream string, sessionID string, sess *session.Session, emit Emitter) (*DNSInterceptor, int, error) {
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, 0, err
	}
	d := &DNSInterceptor{
		sessionID: sessionID,
		sess:      sess,
		emit:      emit,
		pc:        pc,
		done:      make(chan struct{}),
		upstream:  upstream,
	}
	d.wg.Add(1)
	go d.loop()
	return d, pc.LocalAddr().(*net.UDPAddr).Port, nil
}

func (d *DNSInterceptor) Close() error {
	close(d.done)
	err := d.pc.Close()
	d.wg.Wait()
	return err
}

func (d *DNSInterceptor) loop() {
	defer d.wg.Done()
	buf := make([]byte, 4096)
	for {
		_ = d.pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, addr, err := d.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-d.done:
				return
			default:
				continue
			}
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		d.wg.Add(1)
		go func(a net.Addr, msg []byte) {
			defer d.wg.Done()
			_ = d.handle(a, msg)
		}(addr, q)
	}
}

func (d *DNSInterceptor) handle(clientAddr net.Addr, query []byte) error {
	domain := parseDNSDomain(query)
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "dns_query",
		SessionID: d.sessionID,
		CommandID: "",
		Domain:    domain,
		Fields: map[string]any{
			"upstream": d.upstream,
		},
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionAllow,
			EffectiveDecision: types.DecisionAllow,
			Rule:              "dns-monitor-only",
		},
	}
	if d.sess != nil {
		ev.CommandID = d.sess.CurrentCommandID()
	}
	if d.emit != nil {
		_ = d.emit.AppendEvent(context.Background(), ev)
		d.emit.Publish(ev)
	}

	upConn, err := net.Dial("udp", d.upstream)
	if err != nil {
		return err
	}
	defer upConn.Close()
	_ = upConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := upConn.Write(query); err != nil {
		return err
	}
	resp := make([]byte, 4096)
	n, err := upConn.Read(resp)
	if err != nil {
		return err
	}
	_, _ = d.pc.WriteTo(resp[:n], clientAddr)
	return nil
}

func parseDNSDomain(msg []byte) string {
	// Minimal DNS QNAME parser. Best-effort, returns "" on failure.
	if len(msg) < 12 {
		return ""
	}
	i := 12
	var out string
	for {
		if i >= len(msg) {
			return ""
		}
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		// compression not handled
		if l&0xC0 != 0 {
			return ""
		}
		if i+l > len(msg) {
			return ""
		}
		if out != "" {
			out += "."
		}
		out += string(msg[i : i+l])
		i += l
	}
	if out == "" {
		return ""
	}
	return out
}

func (d *DNSInterceptor) String() string {
	return fmt.Sprintf("dns(%s)", d.pc.LocalAddr().String())
}

