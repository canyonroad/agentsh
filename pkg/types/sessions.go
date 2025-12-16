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

