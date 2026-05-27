//go:build linux

package ptrace

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// errScratchUnmapped is returned (wrapped) by ensureScratchPage when the
// injected mmap returns an address that maps no VMA in the tracee (#369). It is
// a sentinel so callers can distinguish this specific "injection produced no
// mapping" outcome from a generic inject failure: the #399 inject self-probe
// treats it as the clean broken-kernel degrade signal (Injectable=false),
// whereas production inject paths treat any error the same (fall back). Test
// with errors.Is.
var errScratchUnmapped = errors.New("scratch mmap mapped no VMA")

// scratchPage tracks a scratch memory page mmap'd into a tracee's address space.
// Per-TGID: threads in the same process share address space.
type scratchPage struct {
	mu   sync.Mutex
	addr uint64 // base address of the mmap'd page
	used int    // bytes used (bump allocator)
	size int    // page size (4096)
}

// allocate returns a pointer to n bytes within the scratch page.
func (s *scratchPage) allocate(n int) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used+n > s.size {
		return 0, fmt.Errorf("scratch page full: used=%d, need=%d, size=%d", s.used, n, s.size)
	}
	addr := s.addr + uint64(s.used)
	s.used += n
	return addr, nil
}

// reset resets the bump allocator. Call at each new syscall-enter stop.
func (s *scratchPage) reset() {
	s.mu.Lock()
	s.used = 0
	s.mu.Unlock()
}

// ensureScratchPage returns the scratch page for the given TGID, allocating one
// via mmap injection if needed.
//
// Note: in practice this is only called from the single-threaded tracer event
// loop, so races are not expected. The double-check pattern is defensive.
func (t *Tracer) ensureScratchPage(tid, tgid int, savedRegs Regs) (*scratchPage, error) {
	t.mu.Lock()
	sp := t.tgidScratch[tgid]
	t.mu.Unlock()

	if sp != nil {
		return sp, nil
	}

	// #369 diagnostic: snapshot the tracee's mappings, inject mmap, then verify
	// the mmap actually created a mapping at the returned address. A new mapping
	// at a different address than addr ⇒ the return register is mis-read; no new
	// mapping ⇒ the injected mmap did not take effect on this kernel.
	mapsBefore := mapStarts(tid)

	// Inject mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
	addr, err := t.injectSyscallRet(tid, savedRegs, unix.SYS_MMAP,
		0, 4096,
		uint64(unix.PROT_READ|unix.PROT_WRITE),
		uint64(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS),
		^uint64(0), // fd = -1
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("mmap injection: %w", err)
	}

	if !addrInMaps(tid, addr) {
		return nil, fmt.Errorf("scratch mmap returned 0x%x but mapped no VMA (#369); new_mappings=%v: %w",
			addr, newMapRanges(tid, mapsBefore), errScratchUnmapped)
	}

	sp = &scratchPage{addr: addr, size: 4096}

	t.mu.Lock()
	// Double-check: another path may have created a scratch page while we
	// were injecting mmap. Use the existing one and let our mapping leak
	// (harmless: it will be unmapped when the process exits).
	if existing := t.tgidScratch[tgid]; existing != nil {
		t.mu.Unlock()
		return existing, nil
	}
	t.tgidScratch[tgid] = sp
	t.mu.Unlock()

	return sp, nil
}

// invalidateScratchPage removes the scratch page for a TGID.
func (t *Tracer) invalidateScratchPage(tgid int) {
	t.mu.Lock()
	delete(t.tgidScratch, tgid)
	t.mu.Unlock()
}

// resetScratchIfPresent resets the bump allocator for the given TGID's scratch
// page, if one exists. Called at each syscall-enter to reclaim space.
//
// This is safe despite sharing per-TGID because the tracer event loop is
// single-threaded: it processes one syscall stop at a time. By the time the
// next thread in the same TGID hits syscall-enter (triggering reset), the
// previous thread's redirected path has already been consumed by the kernel
// during the setRegs+resume sequence.
func (t *Tracer) resetScratchIfPresent(tgid int) {
	t.mu.Lock()
	sp := t.tgidScratch[tgid]
	t.mu.Unlock()
	if sp != nil {
		sp.reset()
	}
}
