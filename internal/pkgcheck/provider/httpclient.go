package provider

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// retryConfig configures the bounded-retry HTTP client.
type retryConfig struct {
	MaxAttempts       int
	BaseBackoff       time.Duration
	MaxBackoff        time.Duration
	RespectRetryAfter bool
	Transport         http.RoundTripper // optional, defaults to http.DefaultTransport
}

// retryClient wraps http.Client with bounded retries on 429/5xx and
// optional Retry-After header handling.
type retryClient struct {
	cfg    retryConfig
	client *http.Client
}

// newRetryClient creates a retryClient with sane defaults if zero values are passed.
func newRetryClient(cfg retryConfig) *retryClient {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 200 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 5 * time.Second
	}
	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &retryClient{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
	}
}

// Do executes the request with bounded retries on 429/5xx.
// The request body, if any, must be replayable — callers should pass a
// *bytes.Reader or similar that can be re-read.
func (c *retryClient) Do(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	var lastErr error
	for attempt := 1; attempt <= c.cfg.MaxAttempts; attempt++ {
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			if attempt == c.cfg.MaxAttempts {
				break
			}
			c.sleep(attempt, nil, req)
			continue
		}

		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		// Retryable status — drain body and try again.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("http status %d", resp.StatusCode)
		if attempt == c.cfg.MaxAttempts {
			break
		}
		c.sleep(attempt, resp, req)
	}

	return nil, fmt.Errorf("retryClient: gave up after %d attempts: %w", c.cfg.MaxAttempts, lastErr)
}

// sleep applies Retry-After (when configured and present) or exponential
// backoff with jitter. Honors context cancellation.
func (c *retryClient) sleep(attempt int, resp *http.Response, req *http.Request) {
	wait := c.backoff(attempt)
	if c.cfg.RespectRetryAfter && resp != nil {
		if h := resp.Header.Get("Retry-After"); h != "" {
			if secs, err := strconv.Atoi(h); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
		}
	}
	if wait > c.cfg.MaxBackoff {
		wait = c.cfg.MaxBackoff
	}

	select {
	case <-time.After(wait):
	case <-req.Context().Done():
	}
}

// backoff returns exponential-with-jitter backoff for the given attempt.
func (c *retryClient) backoff(attempt int) time.Duration {
	exp := time.Duration(1<<uint(attempt-1)) * c.cfg.BaseBackoff
	if exp > c.cfg.MaxBackoff {
		exp = c.cfg.MaxBackoff
	}
	// Full jitter: random in [0, exp].
	jitter := time.Duration(rand.Int63n(int64(exp) + 1))
	return jitter
}

// errMaxAttempts is exposed for tests that want to assert "gave up".
var errMaxAttempts = errors.New("max retry attempts exceeded")
