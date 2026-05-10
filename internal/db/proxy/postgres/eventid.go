//go:build linux

package postgres

import "github.com/google/uuid"

// newEventID returns a UUIDv7 string for event correlation.
// Spec §8: event_id is uuid-v7. uuid v1.6.0 (already a direct dep) ships v7
// support. Falls back to v4 only if v7's random source fails (extremely rare).
func newEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}
