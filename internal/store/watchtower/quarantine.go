package watchtower

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// quarantineWAL renames walDir to "<walDir>.quarantine.<unix-nanos>-<rand4hex>"
// using a probe-then-rename pattern that is collision-resistant under
// rapid restart loops.
//
// Rationale (round-10 Missing A + round-12 Finding 6 from the design
// rounds): the quarantine name encodes both nanosecond-resolution time
// AND a 16-bit random tag so concurrent restarts at the same wall-
// clock instant do not collide on the rename target. The probe-
// before-rename pattern (os.Lstat → os.Rename only on
// fs.ErrNotExist) collapses every "candidate is taken" outcome to a
// single Lstat check, regardless of platform errno mapping for
// destination-exists rename failures (which diverges across Linux,
// macOS APFS, and Windows FS drivers).
//
// Returns the actual quarantine path used so the caller can log it
// after the rename completes (the path is not predictable in advance
// because the random tag changes per attempt).
func quarantineWAL(walDir string) (string, error) {
	const maxAttempts = 8
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var randTag [2]byte
		if _, rerr := rand.Read(randTag[:]); rerr != nil {
			return "", fmt.Errorf("crypto/rand failed for quarantine tag: %w", rerr)
		}
		candidate := fmt.Sprintf("%s.quarantine.%d-%x", walDir, time.Now().UnixNano(), randTag)

		// Probe: if Lstat returns nil, the candidate path is in use
		// (file or directory). Generate a fresh tag and retry.
		// fs.ErrNotExist is the green light to rename; any other
		// Lstat error (permission denied, broken FS) surfaces as a
		// hard failure rather than a silent loop.
		if _, statErr := os.Lstat(candidate); statErr == nil {
			continue
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return "", fmt.Errorf("quarantine probe (attempt %d): %w", attempt, statErr)
		}

		if err := os.Rename(walDir, candidate); err != nil {
			return "", fmt.Errorf("quarantine rename (attempt %d): %w", attempt, err)
		}
		return candidate, nil
	}
	return "", fmt.Errorf("quarantine: exhausted %d attempts (all candidates taken)", maxAttempts)
}
