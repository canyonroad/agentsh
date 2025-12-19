package api

import (
	"context"
	"net"
	"time"

	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// forwardConnectEvents transforms raw BPF connect events into agentsh events.
func forwardConnectEvents(ctx context.Context, in <-chan ebpf.ConnectEvent, emit storeEmitter, sessionID string, commandID string, metrics *metrics.Collector) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}

			fields := map[string]any{
				"pid":    ev.PID,
				"tgid":   ev.TGID,
				"sport":  ev.Sport,
				"dport":  ev.Dport,
				"family": ev.Family,
				"proto":  ev.Protocol,
			}
			var remote string
			if ev.Family == 2 { // AF_INET
				ip := net.IPv4(byte(ev.DstIPv4>>24), byte(ev.DstIPv4>>16), byte(ev.DstIPv4>>8), byte(ev.DstIPv4))
				remote = net.JoinHostPort(ip.String(), itoa(ev.Dport))
			} else {
				ip := net.IP(ev.DstIPv6[:])
				remote = net.JoinHostPort(ip.String(), itoa(ev.Dport))
			}

			out := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Unix(0, int64(ev.TsNs)).UTC(),
				Type:      "net_connect",
				SessionID: sessionID,
				CommandID: commandID,
				Remote:    remote,
				Fields:    fields,
			}
			_ = emit.AppendEvent(context.Background(), out)
			emit.Publish(out)
			if metrics != nil {
				metrics.IncEvent(out.Type)
			}
		}
	}
}

func itoa(v uint16) string {
	b := make([]byte, 0, 5)
	n := int(v)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{'0' + byte(n%10)}, b...)
		n /= 10
	}
	return string(b)
}
