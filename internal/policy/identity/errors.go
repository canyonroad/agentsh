package identity

import "errors"

var (
	// ErrEmptyName is returned when a process identity has no name.
	ErrEmptyName = errors.New("process identity name cannot be empty")

	// ErrUnknownIdentity is returned when an identity is not found.
	ErrUnknownIdentity = errors.New("unknown process identity")
)
