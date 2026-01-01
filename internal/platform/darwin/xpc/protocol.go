package xpc

// RequestType identifies the type of policy check.
type RequestType string

const (
	RequestTypeFile    RequestType = "file"
	RequestTypeNetwork RequestType = "network"
	RequestTypeCommand RequestType = "command"
	RequestTypeSession RequestType = "session"
	RequestTypeEvent   RequestType = "event"
)

// PolicyRequest is sent from the XPC bridge to the Go policy server.
type PolicyRequest struct {
	Type      RequestType `json:"type"`
	Path      string      `json:"path,omitempty"`      // file path or command path
	Operation string      `json:"operation,omitempty"` // read, write, delete, exec
	PID       int32       `json:"pid"`
	SessionID string      `json:"session_id,omitempty"`

	// Network-specific fields
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"` // Valid range: 0-65535
	Domain string `json:"domain,omitempty"`

	// Command-specific fields
	Args []string `json:"args,omitempty"`

	// Event emission
	EventData []byte `json:"event_data,omitempty"`
}

// PolicyResponse is returned from the Go policy server.
type PolicyResponse struct {
	Allow     bool   `json:"allow"`
	Rule      string `json:"rule,omitempty"`
	Message   string `json:"message,omitempty"`
	SessionID string `json:"session_id,omitempty"` // for session lookups
}
