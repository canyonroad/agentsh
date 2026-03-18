//go:build linux

package ptrace

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

type denyAllNetHandler struct{}

func (denyAllNetHandler) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	return NetworkResult{Allow: false}
}

func (denyAllNetHandler) StaticDenySyscalls() []StaticDeny {
	return []StaticDeny{
		{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
		{Nr: unix.SYS_BIND, Errno: int(unix.EACCES)},
	}
}

type allowAllNetHandler struct{}

func (allowAllNetHandler) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	return NetworkResult{Allow: true}
}

func TestCollectStaticDeniesNilHandler(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{TraceNetwork: true, NetworkHandler: nil}}
	denies := tr.collectStaticDenies()
	if len(denies) != 2 {
		t.Fatalf("expected 2 denies for nil handler, got %d", len(denies))
	}
	if denies[0].Nr != unix.SYS_CONNECT || denies[1].Nr != unix.SYS_BIND {
		t.Error("expected connect and bind denies")
	}
}

func TestCollectStaticDeniesWithChecker(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{TraceNetwork: true, NetworkHandler: denyAllNetHandler{}}}
	denies := tr.collectStaticDenies()
	if len(denies) != 2 {
		t.Fatalf("expected 2 denies from checker, got %d", len(denies))
	}
}

func TestCollectStaticDeniesNoChecker(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{TraceNetwork: true, NetworkHandler: allowAllNetHandler{}}}
	denies := tr.collectStaticDenies()
	if len(denies) != 0 {
		t.Fatalf("expected 0 denies for non-checker handler, got %d", len(denies))
	}
}

// allowAllNetWithStatic implements both NetworkHandler and StaticAllowChecker.
type allowAllNetWithStatic struct{}

func (allowAllNetWithStatic) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	return NetworkResult{Allow: true}
}

func (allowAllNetWithStatic) StaticAllowSyscalls() []int {
	return []int{unix.SYS_CONNECT, unix.SYS_BIND}
}

// allowAllFileHandler implements FileHandler and StaticAllowChecker.
type allowAllFileHandler struct{}

func (allowAllFileHandler) HandleFile(_ context.Context, _ FileContext) FileResult {
	return FileResult{Allow: true}
}

func (allowAllFileHandler) StaticAllowSyscalls() []int {
	return []int{unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT}
}

func TestCollectStaticAllowsWithChecker(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{
		TraceNetwork:   true,
		NetworkHandler: allowAllNetWithStatic{},
	}}
	allows := tr.collectStaticAllows()
	if len(allows) != 2 {
		t.Fatalf("expected 2 allows, got %d", len(allows))
	}
	if !allows[unix.SYS_CONNECT] || !allows[unix.SYS_BIND] {
		t.Error("expected connect and bind in allows")
	}
}

func TestCollectStaticAllowsNoChecker(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{
		TraceNetwork:   true,
		NetworkHandler: allowAllNetHandler{},
	}}
	allows := tr.collectStaticAllows()
	if len(allows) != 0 {
		t.Fatalf("expected 0 allows for non-checker handler, got %d", len(allows))
	}
}

func TestCollectStaticAllowsMultipleHandlers(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{
		TraceNetwork:   true,
		TraceFile:      true,
		NetworkHandler: allowAllNetWithStatic{},
		FileHandler:    allowAllFileHandler{},
	}}
	allows := tr.collectStaticAllows()
	// 2 from network + 3 from file = 5
	if len(allows) != 5 {
		t.Fatalf("expected 5 allows from both handlers, got %d", len(allows))
	}
	for _, nr := range []int{unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT} {
		if !allows[nr] {
			t.Errorf("syscall %d missing from allows", nr)
		}
	}
}

func TestCollectStaticAllowsNilHandlers(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{}}
	allows := tr.collectStaticAllows()
	if len(allows) != 0 {
		t.Fatalf("expected 0 allows with nil handlers, got %d", len(allows))
	}
}

func TestValidateStaticDeniesRejectsZeroErrno(t *testing.T) {
	denies := validateStaticDenies([]StaticDeny{
		{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
		{Nr: unix.SYS_BIND, Errno: 0},
	})
	if len(denies) != 1 {
		t.Fatalf("expected 1 valid deny after filtering, got %d", len(denies))
	}
}

func TestValidateStaticDeniesRejectsEscalationOverlap(t *testing.T) {
	denies := validateStaticDenies([]StaticDeny{
		{Nr: unix.SYS_READ, Errno: int(unix.EACCES)},
		{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
	})
	if len(denies) != 1 {
		t.Fatalf("expected 1 valid deny after filtering overlap, got %d", len(denies))
	}
	if denies[0].Nr != unix.SYS_CONNECT {
		t.Error("expected connect to survive, read to be filtered")
	}
}
