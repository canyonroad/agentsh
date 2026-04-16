//go:build !linux || !cgo

package api

// buildBlockListConfigFor returns nil on platforms where seccomp user-notify
// isn't available. The callers pass the result through as `any`, and the
// notify handler is a no-op on these platforms.
func (a *App) buildBlockListConfigFor(_ string) any {
	return nil
}
