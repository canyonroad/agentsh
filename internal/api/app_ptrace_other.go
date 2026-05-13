//go:build !linux

package api

func (a *App) initPtraceTracer()  {}
func (a *App) closePtraceTracer() {}

func (a *App) dbProxySessionResolver() interface {
	ResolveSessionID(pid int32) (string, bool)
} {
	if a.dbProxySessionResolverForTest != nil {
		return a.dbProxySessionResolverForTest
	}
	return nil
}
