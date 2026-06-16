package watchtower

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// productionDialer dials the configured Watchtower endpoint over gRPC,
// honoring TLS and bearer-auth options.
type productionDialer struct {
	opts Options
}

func newGRPCDialerProd(opts Options) transport.Dialer {
	return &productionDialer{opts: opts}
}

func (d *productionDialer) Dial(ctx context.Context) (transport.Conn, error) {
	// Resolve the credential first so a credential error fails fast
	// without opening a socket.
	var bearer string
	if d.opts.CredentialSource != nil {
		b, err := d.opts.CredentialSource.Bearer(ctx)
		if err != nil {
			return nil, fmt.Errorf("watchtower: resolve credential: %w", err)
		}
		bearer = b
	}

	var dialOpts []grpc.DialOption
	if d.opts.TLSEnabled {
		tlsCfg := &tls.Config{InsecureSkipVerify: d.opts.TLSInsecure} //nolint:gosec
		if d.opts.TLSCACertFile != "" {
			pem, err := os.ReadFile(d.opts.TLSCACertFile)
			if err != nil {
				return nil, fmt.Errorf("read TLS CA cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("parse TLS CA cert: no certificates found in %q", d.opts.TLSCACertFile)
			}
			tlsCfg.RootCAs = pool
		}
		if d.opts.TLSCertFile != "" && d.opts.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(d.opts.TLSCertFile, d.opts.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load TLS client cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	//nolint:staticcheck // grpc.DialContext is the established pattern in this codebase.
	cc, err := grpc.DialContext(ctx, d.opts.Endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}

	streamCtx := ctx
	if bearer != "" {
		d.logger().Debug("wtp: presenting credential",
			"kid", credLogID(bearer), "endpoint", d.opts.Endpoint)
		streamCtx = metadata.AppendToOutgoingContext(streamCtx,
			"authorization", "Bearer "+bearer)
	}

	stream, err := wtpv1.NewWatchtowerClient(cc).Stream(streamCtx)
	if err != nil {
		_ = cc.Close()
		if transport.IsAuthReject(err) {
			d.logger().Error("wtp: authentication rejected by Watchtower at stream open",
				"kid", credLogID(bearer), "code", status.Code(err).String())
			return nil, fmt.Errorf("%w: %v", transport.ErrAuthRejected, err)
		}
		return nil, err
	}
	return &grpcStreamConn{stream: stream, cc: cc}, nil
}

// logger returns the configured slog handle or the default.
func (d *productionDialer) logger() *slog.Logger {
	if d.opts.Logger != nil {
		return d.opts.Logger
	}
	return slog.Default()
}

type grpcStreamConn struct {
	stream wtpv1.Watchtower_StreamClient
	cc     *grpc.ClientConn
	closed atomic.Bool
}

func (g *grpcStreamConn) Send(m *wtpv1.ClientMessage) error   { return g.stream.Send(m) }
func (g *grpcStreamConn) Recv() (*wtpv1.ServerMessage, error) { return g.stream.Recv() }

// CloseSend half-closes the send side of the stream. It does NOT
// release the underlying ClientConn — call Close for that.
func (g *grpcStreamConn) CloseSend() error { return g.stream.CloseSend() }

// Close fully tears down the stream by closing the underlying
// ClientConn, which cancels any in-flight Send/Recv. Idempotent so
// error paths can call it without coordinating with a graceful close.
func (g *grpcStreamConn) Close() error {
	if !g.closed.CompareAndSwap(false, true) {
		return nil
	}
	return g.cc.Close()
}
