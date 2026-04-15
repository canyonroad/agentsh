//go:build !linux || !cgo

package api

// resolvableBlockListCount is a no-op on non-linux targets: seccomp
// isn't loaded there, so no ActNotify rules will ever be installed.
// Returning 0 keeps the USER_NOTIF gate closed on these builds.
func resolvableBlockListCount(_ []string) int {
	return 0
}
