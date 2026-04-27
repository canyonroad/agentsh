package ocsf

import (
	"errors"
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
)

// Mapping declares how a single agentsh ev.Type is projected into OCSF.
//
// All four fields are required:
//   - ClassUID and ActivityID end up on the resulting compact.MappedEvent.
//   - FieldsAllowlist is the ONLY way ev.Fields values reach the
//     projector. Sensitive keys are absent from every allowlist; there
//     is no global denylist.
//   - Project builds the class-specific proto.Message. Map() handles
//     the deterministic marshal at the boundary.
type Mapping struct {
	ClassUID        uint32
	ActivityID      uint32
	FieldsAllowlist []FieldRule
	Project         Projector
}

// Projector builds a typed proto.Message for the class. It receives
// only allowlisted-and-transformed Fields values; it must not reach
// ev.Fields directly.
type Projector func(ev types.Event, allowed map[string]any) (proto.Message, error)

// FieldRule declares one allowlisted ev.Fields key plus its transform.
//
// Transform may return (nil, nil) to omit the key from `allowed`. An
// omitted required key is reported as ErrMissingRequiredField.
//
// DestPath is informational (used for documentation and golden test
// readability); the projector decides where the value lands inside the
// proto message.
type FieldRule struct {
	Key       string
	Required  bool
	Transform func(any) (any, error)
	DestPath  string
}

// Errors surfaced by Map() and consumed by the WTP store boundary.
var (
	ErrUnmappedType         = errors.New("ocsf: event Type not registered")
	ErrMissingRequiredField = errors.New("ocsf: required allowlisted field absent or rejected")
	ErrProjectFailed        = errors.New("ocsf: projector failed to build OCSF message")
)

// UnmappedTypeError wraps ErrUnmappedType with the offending Type so
// callers can include it in structured logs.
type UnmappedTypeError struct{ Type string }

func (e *UnmappedTypeError) Error() string {
	return fmt.Sprintf("%s: %q", ErrUnmappedType.Error(), e.Type)
}
func (e *UnmappedTypeError) Unwrap() error { return ErrUnmappedType }

// projectFields runs every FieldRule in the order it appears in the
// allowlist (slice order — deterministic by declaration). Returns a
// fresh map of Key -> transformed value, omitting keys whose transform
// returned (nil, nil). A required key that is absent or whose transform
// returned a non-nil error becomes ErrMissingRequiredField.
//
// The mapper's iteration order is the slice's order; this function MUST
// NOT range over `fields` directly (Go map iteration is randomized,
// breaking determinism).
func projectFields(fields map[string]any, rules []FieldRule) (map[string]any, error) {
	out := make(map[string]any, len(rules))
	for _, r := range rules {
		raw, present := fields[r.Key]
		if !present {
			if r.Required {
				return nil, fmt.Errorf("%w: %s", ErrMissingRequiredField, r.Key)
			}
			continue
		}
		var v any
		var err error
		if r.Transform != nil {
			v, err = r.Transform(raw)
		} else {
			v = raw
		}
		if err != nil {
			if r.Required {
				return nil, fmt.Errorf("%w: %s: %v", ErrMissingRequiredField, r.Key, err)
			}
			continue // non-required: drop silently
		}
		if v == nil {
			if r.Required {
				return nil, fmt.Errorf("%w: %s: transform returned nil", ErrMissingRequiredField, r.Key)
			}
			continue
		}
		out[r.Key] = v
	}
	return out, nil
}

// safeProject runs the projector under a recover() guard. Any panic is
// converted into ErrProjectFailed with the panic value in the wrapped
// message.
func safeProject(p Projector, ev types.Event, allowed map[string]any) (msg proto.Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			msg = nil
			err = fmt.Errorf("%w: panic: %v", ErrProjectFailed, r)
		}
	}()
	msg, err = p(ev, allowed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProjectFailed, err)
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: projector returned nil message", ErrProjectFailed)
	}
	return msg, nil
}

// allowlistKeys returns the sorted slice of keys an allowlist projects.
// Used by the exhaustiveness Fields-key check.
func allowlistKeys(rules []FieldRule) []string {
	keys := make([]string, len(rules))
	for i, r := range rules {
		keys[i] = r.Key
	}
	sort.Strings(keys)
	return keys
}

// Common transforms reused across registry entries.

// AsString stringifies common scalar concrete types behind an `any`.
// Returns (nil, nil) for nil input. Errors only on types it cannot
// reasonably stringify.
func AsString(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case string:
		return x, nil
	case []byte:
		return string(x), nil
	case int, int32, int64, uint, uint32, uint64, float32, float64, bool:
		return fmt.Sprintf("%v", x), nil
	default:
		return nil, fmt.Errorf("AsString: unsupported %T", v)
	}
}

// AsUint32 narrows numeric concrete types to uint32. Errors on overflow.
func AsUint32(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case int:
		if x < 0 || x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: out of range: %d", x)
		}
		return uint32(x), nil
	case int32:
		if x < 0 {
			return nil, fmt.Errorf("AsUint32: negative: %d", x)
		}
		return uint32(x), nil
	case int64:
		if x < 0 || x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: out of range: %d", x)
		}
		return uint32(x), nil
	case uint32:
		return x, nil
	case uint64:
		if x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: overflow: %d", x)
		}
		return uint32(x), nil
	case float64:
		if x < 0 || x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: out of range: %v", x)
		}
		return uint32(x), nil
	default:
		return nil, fmt.Errorf("AsUint32: unsupported %T", v)
	}
}

// AsUint64 narrows numeric concrete types to uint64.
func AsUint64(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case int:
		if x < 0 {
			return nil, fmt.Errorf("AsUint64: negative: %d", x)
		}
		return uint64(x), nil
	case int64:
		if x < 0 {
			return nil, fmt.Errorf("AsUint64: negative: %d", x)
		}
		return uint64(x), nil
	case uint64:
		return x, nil
	case uint32:
		return uint64(x), nil
	case float64:
		if x < 0 {
			return nil, fmt.Errorf("AsUint64: negative: %v", x)
		}
		return uint64(x), nil
	default:
		return nil, fmt.Errorf("AsUint64: unsupported %T", v)
	}
}
