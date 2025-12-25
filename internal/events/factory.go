package events

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

// EventConfig controls event generation behavior.
type EventConfig struct {
	// Include IP addresses in events
	IncludeNetworkInfo bool `yaml:"include_network_info"`

	// Include MAC address in events
	IncludeMACAddress bool `yaml:"include_mac_address"`

	// Enable path/content sanitization
	SanitizePaths bool `yaml:"sanitize_paths"`

	// Custom sanitization patterns
	SanitizePatterns SanitizePatterns `yaml:"sanitize_patterns"`

	// Default metadata added to all events
	DefaultMetadata map[string]string `yaml:"default_metadata"`

	// Default tags added to all events
	DefaultTags []string `yaml:"default_tags"`

	// Default labels added to all events
	DefaultLabels map[string]string `yaml:"default_labels"`
}

// DefaultEventConfig returns sensible defaults.
func DefaultEventConfig() *EventConfig {
	return &EventConfig{
		IncludeNetworkInfo: true,
		IncludeMACAddress:  false,
		SanitizePaths:      true,
		SanitizePatterns:   DefaultSensitivePatterns,
		DefaultMetadata:    map[string]string{},
		DefaultTags:        []string{},
		DefaultLabels:      map[string]string{},
	}
}

// EventFactory creates events with pre-populated base fields.
type EventFactory struct {
	ctx       *RuntimeContext
	sessionID string
	sequence  int64
	sanitizer *Sanitizer
	config    *EventConfig
}

// NewEventFactory creates a factory for a session.
func NewEventFactory(ctx *RuntimeContext, sessionID string, config *EventConfig) *EventFactory {
	if config == nil {
		config = DefaultEventConfig()
	}
	return &EventFactory{
		ctx:       ctx,
		sessionID: sessionID,
		config:    config,
		sanitizer: NewSanitizer(config.SanitizePatterns),
	}
}

// NewEvent creates a new event with all base fields populated.
func (f *EventFactory) NewEvent(eventType EventType, pid int) *BaseEvent {
	now := time.Now()
	seq := atomic.AddInt64(&f.sequence, 1)

	event := &BaseEvent{
		// Identity
		Hostname:         f.ctx.Hostname,
		MachineID:        f.ctx.MachineID,
		ContainerID:      f.ctx.ContainerID,
		ContainerImage:   f.ctx.ContainerImage,
		ContainerRuntime: f.ctx.ContainerRuntime,
		K8sNamespace:     f.ctx.K8sNamespace,
		K8sPod:           f.ctx.K8sPod,
		K8sNode:          f.ctx.K8sNode,
		K8sCluster:       f.ctx.K8sCluster,

		// Timestamp
		Timestamp:       now.Format("2006-01-02T15:04:05.000000Z07:00"),
		TimestampUnixUS: now.UnixMicro(),
		MonotonicNS:     now.UnixNano(),
		Sequence:        seq,

		// OS
		OS:            f.ctx.OS,
		OSVersion:     f.ctx.OSVersion,
		OSDistro:      f.ctx.OSDistro,
		KernelVersion: f.ctx.KernelVersion,
		Arch:          f.ctx.Arch,

		// Platform
		PlatformVariant: f.ctx.PlatformVariant,
		FSBackend:       f.ctx.FSBackend,
		NetBackend:      f.ctx.NetBackend,
		ProcessBackend:  f.ctx.ProcessBackend,
		IPCBackend:      f.ctx.IPCBackend,

		// Version
		AgentshVersion:     f.ctx.AgentshVersion,
		AgentshCommit:      f.ctx.AgentshCommit,
		AgentshBuildTime:   f.ctx.AgentshBuildTime,
		EventSchemaVersion: f.ctx.EventSchemaVersion,

		// Correlation
		EventID:   generateEventID(),
		SessionID: f.sessionID,

		// Process
		PID: pid,

		// Type
		Type:     eventType,
		Category: EventCategory[eventType],

		// Custom metadata
		Metadata: f.config.DefaultMetadata,
		Tags:     f.config.DefaultTags,
		Labels:   f.config.DefaultLabels,
	}

	// Network info (if configured)
	if f.config.IncludeNetworkInfo {
		event.IPv4Addresses = f.ctx.IPv4Addresses
		event.IPv6Addresses = f.ctx.IPv6Addresses
		event.PrimaryInterface = f.ctx.PrimaryInterface
	}
	if f.config.IncludeMACAddress {
		event.MACAddress = f.ctx.MACAddress
	}

	return event
}

// SetCommandID sets the command ID for correlation.
func (f *EventFactory) SetCommandID(event *BaseEvent, commandID string) {
	event.CommandID = commandID
}

// SetTraceContext sets OpenTelemetry trace context.
func (f *EventFactory) SetTraceContext(event *BaseEvent, traceID, spanID, parentSpanID string) {
	event.TraceID = traceID
	event.SpanID = spanID
	event.ParentSpanID = parentSpanID
	event.TraceFlags = "01" // sampled
}

// SetDecision sets policy decision information.
func (f *EventFactory) SetDecision(event *BaseEvent, decision, rule string) {
	event.Decision = decision
	event.PolicyRule = rule
}

// SetError sets error context.
func (f *EventFactory) SetError(event *BaseEvent, err error, code string, errno int) {
	if err != nil {
		event.Error = err.Error()
	}
	event.ErrorCode = code
	event.Errno = errno
}

// SanitizePath sanitizes a path if configured.
func (f *EventFactory) SanitizePath(event *BaseEvent, path string) string {
	if !f.config.SanitizePaths {
		return path
	}
	sanitized, fields := f.sanitizer.SanitizePath(path)
	if len(fields) > 0 {
		event.SanitizedFields = append(event.SanitizedFields, fields...)
		event.SanitizationReason = "sensitive_path_pattern"
	}
	return sanitized
}

// SanitizeCmdline sanitizes command line arguments if configured.
func (f *EventFactory) SanitizeCmdline(event *BaseEvent, cmdline []string) []string {
	if !f.config.SanitizePaths {
		return cmdline
	}
	return f.sanitizer.SanitizeCmdline(cmdline)
}

func generateEventID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("evt-%x-%s", time.Now().UnixNano(), hex.EncodeToString(b))
}
