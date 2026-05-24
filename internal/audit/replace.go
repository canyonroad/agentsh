package audit

import "time"

// Tunables for the Windows atomic-replace retry. On Windows, MoveFileEx with
// MOVEFILE_REPLACE_EXISTING can return ERROR_ACCESS_DENIED / ERROR_SHARING_
// VIOLATION when another handle briefly holds the destination sidecar open
// (a concurrent reader, antivirus, or the search indexer). Those clear within
// a few milliseconds; replaceMaxAttempts × replaceBackoff bounds the wait at
// roughly 200ms before surfacing the error.
const (
	replaceMaxAttempts = 10
	replaceBackoff     = 20 * time.Millisecond
)

// retryReplace invokes move, retrying up to maxAttempts total times on errors
// the transient predicate accepts, sleeping backoff between attempts. A
// non-transient error returns immediately; exhausting all attempts returns the
// last error. move/transient/sleep are injected so the retry behavior is
// testable without a real filesystem race. Used by the Windows replaceFile
// (see fsync_dir_windows.go); the unix path uses os.Rename, which does not
// suffer this race.
func retryReplace(move func() error, transient func(error) bool, maxAttempts int, backoff time.Duration, sleep func(time.Duration)) error {
	if maxAttempts < 1 {
		maxAttempts = 1 // always attempt the move at least once
	}
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err = move(); err == nil {
			return nil
		}
		if !transient(err) {
			return err
		}
		if attempt < maxAttempts-1 {
			sleep(backoff)
		}
	}
	return err
}
