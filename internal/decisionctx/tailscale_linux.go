//go:build linux

package decisionctx

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

const defaultTailscaleSocket = "/run/tailscale/tailscaled.sock"

// defaultTailscaleStatus queries the tailscaled local API over its unix
// socket. Avoids depending on the heavy tailscale.com module.
func defaultTailscaleStatus(ctx context.Context, socket string) (string, bool, error) {
	if socket == "" {
		socket = defaultTailscaleSocket
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
	defer client.CloseIdleConnections()
	// Host is ignored by the unix dialer but required to form a valid URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://local-tailscaled.sock/localapi/v0/status", nil)
	if err != nil {
		return "", false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, nil // dial/connect failure => tailscaled absent, not an error
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", false, err
	}
	login, ok := parseTailscaleStatus(body)
	return login, ok, nil
}
