// Command wtp-testserver runs a hermetic WTP server bound to a local TCP
// port. Useful for manual integration testing — it has no auth, accepts
// any client, and prints batch summaries to stderr.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7080", "bind address")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	wtpv1.RegisterWatchtowerServer(srv, &handler{})

	fmt.Fprintf(os.Stderr, "wtp-testserver listening on %s\n", *addr)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Fprintln(os.Stderr, "shutting down")
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

type handler struct {
	wtpv1.UnimplementedWatchtowerServer
}

func (h *handler) Stream(stream wtpv1.Watchtower_StreamServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *wtpv1.ClientMessage_SessionInit:
			fmt.Fprintf(os.Stderr, "session init: agent=%s session=%s\n",
				m.SessionInit.GetAgentId(), m.SessionInit.GetSessionId())
			_ = stream.Send(&wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_SessionAck{
					SessionAck: &wtpv1.SessionAck{},
				},
			})
		case *wtpv1.ClientMessage_EventBatch:
			events := m.EventBatch.GetUncompressed().GetEvents()
			fmt.Fprintf(os.Stderr, "batch: %d records\n", len(events))
			lastSeq := uint64(0)
			lastGen := uint32(0)
			if n := len(events); n > 0 {
				lastSeq = events[n-1].GetSequence()
				lastGen = events[n-1].GetGeneration()
			}
			_ = stream.Send(&wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_BatchAck{
					BatchAck: &wtpv1.BatchAck{
						AckHighWatermarkSeq: lastSeq,
						Generation:          lastGen,
					},
				},
			})
		case *wtpv1.ClientMessage_Heartbeat:
			// no-op
		}
	}
}
