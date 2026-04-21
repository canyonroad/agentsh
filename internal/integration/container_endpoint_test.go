//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/docker/go-connections/nat"
)

type containerEndpointSource interface {
	Host(context.Context) (string, error)
	MappedPort(context.Context, nat.Port) (nat.Port, error)
}

func containerHTTPEndpointWithRetry(ctx context.Context, ctr containerEndpointSource, port string) (string, error) {
	const (
		maxAttempts    = 3
		attemptTimeout = 5 * time.Second
		retryBackoff   = 250 * time.Millisecond
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		host, err := ctr.Host(attemptCtx)
		if err == nil {
			mappedPort, mapErr := ctr.MappedPort(attemptCtx, nat.Port(port))
			if mapErr == nil {
				cancel()
				return "http://" + net.JoinHostPort(host, mappedPort.Port()), nil
			}
			err = mapErr
		}
		cancel()

		lastErr = err
		if !isTransientContainerEndpointError(err) || attempt == maxAttempts || ctx.Err() != nil {
			return "", err
		}
		time.Sleep(retryBackoff)
	}

	return "", lastErr
}

func isTransientContainerEndpointError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "inspect:")
}
