package transport

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrAuthRejected marks a WTP connection failure caused by the server
// rejecting the presented credential (gRPC Unauthenticated /
// PermissionDenied) at stream open or handshake. The Run loop treats it
// specially: it is recoverable (a rotated file credential, or a Phase-2
// refreshing source, can succeed on a later Dial) but must NOT fast-retry,
// so reconnect backoff is clamped to its max for this case.
var ErrAuthRejected = errors.New("wtp: authentication rejected by Watchtower")

// IsAuthReject reports whether err is (or wraps) an authentication
// rejection — either the ErrAuthRejected sentinel or a raw gRPC status
// with code Unauthenticated/PermissionDenied (which is how the reject
// first surfaces from Dial/Recv before it is wrapped).
func IsAuthReject(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAuthRejected) {
		return true
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	default:
		return false
	}
}
