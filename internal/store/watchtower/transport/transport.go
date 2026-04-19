package transport

import (
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Options configures a Transport.
type Options struct {
	Dialer    Dialer
	AgentID   string
	SessionID string
	// FormatVersion is sent in SessionInit; defaults to 2.
	FormatVersion uint32
}

// Transport runs the four-state WTP client state machine. It is owned by
// a single goroutine — callers interact via channels.
type Transport struct {
	opts Options
	conn Conn

	// last acknowledged watermark, updated when SessionAck/SessionUpdate
	// is observed.
	ackedSequence   uint64
	ackedGeneration uint32
}

// New constructs a Transport. It does not dial; call Run to start.
func New(opts Options) *Transport {
	if opts.FormatVersion == 0 {
		opts.FormatVersion = 2
	}
	return &Transport{opts: opts}
}

// sessionInit returns the SessionInit message for the current connection.
func (t *Transport) sessionInit() *wtpv1.ClientMessage {
	return &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				AgentId:             t.opts.AgentID,
				SessionId:           t.opts.SessionID,
				FormatVersion:       t.opts.FormatVersion,
				WalHighWatermarkSeq: t.ackedSequence,
				Generation:          t.ackedGeneration,
			},
		},
	}
}
