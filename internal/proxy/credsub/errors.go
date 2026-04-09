package credsub

import "errors"

// ErrLengthMismatch is returned by Table.Add when the length of the
// fake byte slice does not equal the length of the real byte slice.
// Length preservation is required for in-place byte rewriting and to
// avoid recomputing Content-Length at substitution time.
var ErrLengthMismatch = errors.New("credsub: fake and real must have equal length")

// ErrEmptyValue is returned by Table.Add when either the fake or real
// slice is zero-length. A zero-length pattern would match every
// position in any body and is never a valid credential.
var ErrEmptyValue = errors.New("credsub: fake and real must be nonempty")

// ErrServiceExists is returned by Table.Add when a service name is
// already registered in the table. Each service has at most one
// (fake, real) pair per session.
var ErrServiceExists = errors.New("credsub: service already registered")

// ErrFakeCollision is returned by Table.Add when the new fake exactly
// equals an existing entry's fake, when the new fake exactly equals
// an existing entry's real, or when the new real exactly equals an
// existing entry's fake. Any of these would cause substitution to
// double-swap and corrupt data.
var ErrFakeCollision = errors.New("credsub: fake or real collides with existing entry")
