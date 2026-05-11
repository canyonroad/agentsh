//go:build linux

package linux

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
)

// TestFilesystem_MountTeardownRaceUnderLoad is a functional regression
// test: it drives the real Filesystem.Mount -> file activity -> m.Close()
// teardown path under concurrency and asserts
// (a) the process survives -- no "send on closed
// channel" panic
// (b) the event channel is cleanly closed by teardown, so the consumer
// goroutine exits instead of leaking.
//
// The session-teardown closure used to close eventChan directly while FUSE
// handlers could still be mid-AppendEvent; a send on the closed channel
// panicked and crashed the whole daemon. Now m.Close() quiesces the emitter
// (done flag set before close) and the recover guard covers the residual
// window between the done check and the send.
//
// Skips where /dev/fuse is unavailable or the mount needs privileges the
// test host does not have.
func TestFilesystem_MountTeardownRaceUnderLoad(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("FUSE not available: %v", err)
	}
	fs := NewFilesystem()
	if !fs.Available() {
		t.Skip("Filesystem reports unavailable")
	}

	const iterations = 20
	for i := 0; i < iterations; i++ {
		backing := t.TempDir()
		mountPoint := filepath.Join(t.TempDir(), "mnt")
		if err := os.MkdirAll(mountPoint, 0o755); err != nil {
			t.Fatalf("iteration %d: mkdir mountpoint: %v", i, err)
		}

		eventChan := make(chan platform.IOEvent, 64)
		// Drain goroutine: ranges until eventChan is closed. The only thing
		// that closes it is m.Close() -> closeEmitter() -> emitter.Close().
		// If teardown fails to close the channel, this goroutine leaks and
		// the drainDone wait below times out.
		drainDone := make(chan struct{})
		go func() {
			for range eventChan {
			}
			close(drainDone)
		}()

		cfg := platform.FSConfig{
			SourcePath:   backing,
			MountPoint:   mountPoint,
			SessionID:    "race-session",
			EventChannel: eventChan,
		}
		mount, err := fs.Mount(cfg)
		if err != nil {
			// Mount can fail on hosts without privileges/allow_other.
			// Close the channel ourselves so the drain goroutine exits,
			// then skip -- there is nothing to exercise here.
			close(eventChan)
			<-drainDone
			t.Skipf("iteration %d: Mount failed (may require privileges): %v", i, err)
		}

		// Hammer the mount from several goroutines. Each op goes through a
		// FUSE handler -> emitFileEvent -> AppendEvent -> channel send, so
		// these race m.Close() below.
		var wg sync.WaitGroup
		stop := make(chan struct{})
		const workers = 8
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for n := 0; ; n++ {
					select {
					case <-stop:
						return
					default:
					}
					p := filepath.Join(mountPoint, fmt.Sprintf("f-%d-%d", w, n))
					// Errors are expected once m.Close() unmounts (ENOTCONN/
					// ENOENT); they are not a test failure.
					_ = os.WriteFile(p, []byte("x"), 0o644)
					_, _ = os.Stat(p)
					_ = os.Remove(p)
				}
			}(w)
		}

		// Let workers ramp up so ops are genuinely in flight, then tear the
		// mount down underneath them.
		time.Sleep(15 * time.Millisecond)
		closeErr := mount.Close()
		close(stop)
		wg.Wait()

		// m.Close() must have closed eventChan via the emitter; the drain
		// goroutine therefore exits. A timeout means the channel was never
		// closed -- the leak this PR also fixes.
		select {
		case <-drainDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: eventChan not closed by m.Close() "+
				"(drain goroutine leaked)", i)
		}

		// Unmount may legitimately report an error under heavy load (e.g.
		// EBUSY); the teardown-race behavior asserted above is what
		// this test cares about. Surface it for diagnosis only.
		if closeErr != nil {
			t.Logf("iteration %d: mount.Close() returned %v "+
				"(non-fatal: test asserts no panic and no channel leak)", i, closeErr)
		}
		// Always defensively detach with fusermount(3) so a
		// not-fully-cleaned-up FUSE mount does not break t.TempDir()
		// removal at the end of the test. unix.Unmount(MNT_DETACH)
		// would need CAP_SYS_ADMIN and silently fails as an
		// unprivileged user; fusermount is suid and works.
		for _, bin := range []string{"fusermount3", "fusermount"} {
			if _, err := exec.LookPath(bin); err == nil {
				_ = exec.Command(bin, "-u", "-z", mountPoint).Run()
				break
			}
		}
	}
}
