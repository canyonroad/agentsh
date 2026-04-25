package transport

import (
	"context"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// HeartbeatSender is the subset of Conn that RunHeartbeat needs.
type HeartbeatSender interface {
	Send(*wtpv1.ClientMessage) error
}

// RunHeartbeat periodically posts Heartbeat messages to conn until ctx is
// cancelled or stop is closed. Send errors terminate the loop.
func RunHeartbeat(ctx context.Context, conn HeartbeatSender, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-t.C:
			msg := &wtpv1.ClientMessage{
				Msg: &wtpv1.ClientMessage_Heartbeat{
					Heartbeat: &wtpv1.Heartbeat{},
				},
			}
			if err := conn.Send(msg); err != nil {
				return
			}
		}
	}
}
