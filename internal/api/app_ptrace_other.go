//go:build !linux

package api

func (a *App) initPtraceTracer()  {}
func (a *App) closePtraceTracer() {}
