package types

import "time"

type SessionState string

const (
	SessionStateCreating SessionState = "creating"
	SessionStateReady    SessionState = "ready"
	SessionStateBusy     SessionState = "busy"
	SessionStateStopping SessionState = "stopping"
)

type Session struct {
	ID        string       `json:"id"`
	State     SessionState `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	Workspace string       `json:"workspace"`
	Policy    string       `json:"policy"`

	Cwd string `json:"cwd"`
}

type CreateSessionRequest struct {
	ID        string `json:"id,omitempty"`
	Workspace string `json:"workspace"`
	Policy    string `json:"policy,omitempty"`
}

type SessionPatchRequest struct {
	Cwd   string            `json:"cwd,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
	Unset []string          `json:"unset,omitempty"`
}
