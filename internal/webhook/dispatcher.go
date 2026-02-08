package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// Dispatcher manages multiple webhook configurations and dispatches events to them.
type Dispatcher struct {
	mu       sync.RWMutex
	webhooks map[string]*WebhookConfig
	client   *http.Client
}

// WebhookConfig defines a webhook endpoint and its configuration.
type WebhookConfig struct {
	// Name is a unique identifier for this webhook.
	Name string `yaml:"name" json:"name"`

	// URL is the webhook endpoint URL.
	URL string `yaml:"url" json:"url"`

	// Method is the HTTP method (default: POST).
	Method string `yaml:"method" json:"method"`

	// Headers are additional HTTP headers to include.
	Headers map[string]string `yaml:"headers" json:"headers"`

	// Template is a Go template for the request body.
	// If empty, events are sent as JSON.
	Template string `yaml:"template" json:"template"`

	// Events is a list of event types to send to this webhook.
	// Use "*" to match all events.
	Events []string `yaml:"events" json:"events"`

	// BatchSize is the number of events to batch before sending.
	BatchSize int `yaml:"batch_size" json:"batch_size"`

	// FlushInterval is how often to flush the batch.
	FlushInterval time.Duration `yaml:"flush_interval" json:"flush_interval"`

	// Timeout is the HTTP request timeout.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Enabled indicates if this webhook is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// RetryCount is the number of retries on failure.
	RetryCount int `yaml:"retry_count" json:"retry_count"`

	// RetryDelay is the delay between retries.
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`

	// compiled template
	tmpl *template.Template

	// event matching set
	eventSet map[string]bool

	// batching state
	mu        sync.Mutex
	buf       []types.Event
	lastFlush time.Time
}

// NewDispatcher creates a new webhook dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		webhooks: make(map[string]*WebhookConfig),
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Register adds a webhook configuration.
func (d *Dispatcher) Register(cfg *WebhookConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Set defaults
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1 // No batching by default
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	// Compile template if provided
	if cfg.Template != "" {
		tmpl, err := template.New(cfg.Name).Parse(cfg.Template)
		if err != nil {
			return fmt.Errorf("invalid template: %w", err)
		}
		cfg.tmpl = tmpl
	}

	// Build event set for matching
	cfg.eventSet = make(map[string]bool)
	for _, e := range cfg.Events {
		cfg.eventSet[e] = true
	}

	cfg.lastFlush = time.Now().UTC()
	d.webhooks[cfg.Name] = cfg
	return nil
}

// Unregister removes a webhook configuration.
func (d *Dispatcher) Unregister(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.webhooks, name)
}

// Dispatch sends an event to all matching webhooks.
func (d *Dispatcher) Dispatch(ctx context.Context, event types.Event) {
	d.mu.RLock()
	webhooks := make([]*WebhookConfig, 0, len(d.webhooks))
	for _, wh := range d.webhooks {
		if wh.Enabled && wh.matchesEvent(event.Type) {
			webhooks = append(webhooks, wh)
		}
	}
	d.mu.RUnlock()

	for _, wh := range webhooks {
		wh.addEvent(ctx, event, d.client)
	}
}

// DispatchBatch sends multiple events to all matching webhooks.
func (d *Dispatcher) DispatchBatch(ctx context.Context, events []types.Event) {
	for _, ev := range events {
		d.Dispatch(ctx, ev)
	}
}

// Flush forces all webhooks to flush their buffers.
func (d *Dispatcher) Flush(ctx context.Context) {
	d.mu.RLock()
	webhooks := make([]*WebhookConfig, 0, len(d.webhooks))
	for _, wh := range d.webhooks {
		webhooks = append(webhooks, wh)
	}
	d.mu.RUnlock()

	for _, wh := range webhooks {
		wh.flush(ctx, d.client)
	}
}

// matchesEvent checks if an event type matches this webhook's filter.
func (c *WebhookConfig) matchesEvent(eventType string) bool {
	if len(c.eventSet) == 0 || c.eventSet["*"] {
		return true
	}
	if c.eventSet[eventType] {
		return true
	}
	// Check for wildcard patterns like "file_*"
	for pattern := range c.eventSet {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(eventType, prefix) {
				return true
			}
		}
	}
	return false
}

// addEvent adds an event to the buffer and flushes if needed.
func (c *WebhookConfig) addEvent(ctx context.Context, event types.Event, client *http.Client) {
	c.mu.Lock()
	c.buf = append(c.buf, event)
	shouldFlush := len(c.buf) >= c.BatchSize ||
		(c.FlushInterval > 0 && time.Since(c.lastFlush) >= c.FlushInterval)
	var toSend []types.Event
	if shouldFlush {
		toSend = c.buf
		c.buf = nil
		c.lastFlush = time.Now().UTC()
	}
	c.mu.Unlock()

	if len(toSend) > 0 {
		go c.send(ctx, toSend, client)
	}
}

// flush forces a flush of the buffer.
func (c *WebhookConfig) flush(ctx context.Context, client *http.Client) {
	c.mu.Lock()
	toSend := c.buf
	c.buf = nil
	c.lastFlush = time.Now().UTC()
	c.mu.Unlock()

	if len(toSend) > 0 {
		c.send(ctx, toSend, client)
	}
}

// send sends events to the webhook endpoint.
func (c *WebhookConfig) send(ctx context.Context, events []types.Event, client *http.Client) {
	var body []byte
	var err error

	if c.tmpl != nil {
		// Use template to render body
		data := map[string]any{
			"Events": events,
			"Event":  events[0], // For single-event templates
			"Count":  len(events),
		}
		var buf bytes.Buffer
		if err := c.tmpl.Execute(&buf, data); err != nil {
			// Log error but continue
			return
		}
		body = buf.Bytes()
	} else {
		// Send as JSON
		if len(events) == 1 && c.BatchSize <= 1 {
			body, err = json.Marshal(events[0])
		} else {
			body, err = json.Marshal(events)
		}
		if err != nil {
			return
		}
	}

	// Send with retries
	for attempt := 0; attempt <= c.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(c.RetryDelay)
		}

		reqCtx, cancel := context.WithTimeout(ctx, c.Timeout)
		req, err := http.NewRequestWithContext(reqCtx, c.Method, c.URL, bytes.NewReader(body))
		if err != nil {
			cancel()
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		cancel()
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return // Success
		}
	}
}

// List returns all registered webhook names.
func (d *Dispatcher) List() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	names := make([]string, 0, len(d.webhooks))
	for name := range d.webhooks {
		names = append(names, name)
	}
	return names
}

// Get returns a webhook configuration by name.
func (d *Dispatcher) Get(name string) *WebhookConfig {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.webhooks[name]
}

// SlackWebhook creates a webhook config for Slack.
func SlackWebhook(name, url string, events []string) WebhookConfig {
	return WebhookConfig{
		Name:    name,
		URL:     url,
		Method:  http.MethodPost,
		Headers: map[string]string{"Content-Type": "application/json"},
		Template: `{
  "text": "{{.Event.Type}} in session {{.Event.SessionID}}",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*{{.Event.Type}}*\nSession: {{.Event.SessionID}}"
      }
    }
  ]
}`,
		Events:    events,
		BatchSize: 1,
		Timeout:   5 * time.Second,
		Enabled:   true,
	}
}

// PagerDutyWebhook creates a webhook config for PagerDuty.
func PagerDutyWebhook(name, url, routingKey string, events []string) WebhookConfig {
	return WebhookConfig{
		Name:   name,
		URL:    url,
		Method: http.MethodPost,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Template: `{
  "routing_key": "` + routingKey + `",
  "event_action": "trigger",
  "payload": {
    "summary": "{{.Event.Type}}: {{.Event.Path}}",
    "source": "agentsh",
    "severity": "warning",
    "custom_details": {
      "session_id": "{{.Event.SessionID}}",
      "command_id": "{{.Event.CommandID}}",
      "timestamp": "{{.Event.Timestamp}}"
    }
  }
}`,
		Events:     events,
		BatchSize:  1,
		Timeout:    5 * time.Second,
		RetryCount: 2,
		RetryDelay: time.Second,
		Enabled:    true,
	}
}

// GenericWebhook creates a simple JSON webhook config.
func GenericWebhook(name, url string, events []string) WebhookConfig {
	return WebhookConfig{
		Name:          name,
		URL:           url,
		Method:        http.MethodPost,
		Headers:       map[string]string{"Content-Type": "application/json"},
		Events:        events,
		BatchSize:     100,
		FlushInterval: 5 * time.Second,
		Timeout:       10 * time.Second,
		Enabled:       true,
	}
}
