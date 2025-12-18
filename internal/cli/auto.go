package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func autoDisabled() bool {
	v := strings.TrimSpace(os.Getenv("AGENTSH_NO_AUTO"))
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func shouldAutoStartServer(serverAddr string) bool {
	u, err := url.Parse(serverAddr)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	port := u.Port()
	return port == "" || port == "8080"
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded:
			return true
		}
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return true
		}
		err = ue.Err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

func ensureServerRunning(ctx context.Context, serverAddr string, log io.Writer) error {
	if log == nil {
		log = io.Discard
	}
	if !shouldAutoStartServer(serverAddr) {
		return fmt.Errorf("server not reachable at %s", serverAddr)
	}

	if err := waitForHealth(ctx, serverAddr, 150*time.Millisecond); err == nil {
		return nil
	}

	configPath := strings.TrimSpace(os.Getenv("AGENTSH_CONFIG"))
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	fmt.Fprintf(log, "agentsh: auto-starting server (config %s)\n", configPath)

	cmd := exec.Command(os.Args[0], "server", "--config", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("auto-start server: %w", err)
	}
	_ = cmd.Process.Release()

	if err := waitForHealth(ctx, serverAddr, 5*time.Second); err != nil {
		return fmt.Errorf("server did not become ready: %w", err)
	}
	return nil
}

func waitForHealth(ctx context.Context, serverAddr string, timeout time.Duration) error {
	u, err := url.Parse(serverAddr)
	if err != nil {
		return err
	}
	u.Path = "/health"
	u.RawQuery = ""
	u.Fragment = ""

	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 250 * time.Millisecond}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("health check timeout")
}
