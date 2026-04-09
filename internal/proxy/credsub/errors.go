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

// ErrFakeCollision is returned by Table.Add when the new (fake, real)
// pair would corrupt substitution. The covered cases are:
//
//   - The new fake equals the new real (same Add call). This would
//     leak the real credential into agent-visible space because
//     ReplaceRealToFake on a response containing the real value would
//     return that same value, and the agent would treat it as the
//     fake.
//   - The new fake exactly equals an existing entry's fake.
//   - The new fake exactly equals an existing entry's real.
//   - The new real exactly equals an existing entry's fake.
//   - The new real exactly equals an existing entry's real. Two
//     services sharing the same upstream credential makes
//     ReplaceRealToFake ambiguous: the real value would be rewritten
//     to whichever fake was registered first, returning the wrong
//     service token to the agent.
//
// Any of these would cause substitution to double-swap, leak the real
// credential, or corrupt data, so Add rejects them up front.
var ErrFakeCollision = errors.New("credsub: fake or real collides with existing entry")
