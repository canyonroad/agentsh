//go:build windows

package audit

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

func syncDir(string) error { return nil }

// moveFileReplace performs the raw atomic replace via MoveFileEx.
func moveFileReplace(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// isTransientReplaceErr reports whether a MoveFileEx failure is the transient
// kind caused by another handle briefly holding the destination open. Windows
// surfaces this as ERROR_ACCESS_DENIED (a concurrent reader without
// FILE_SHARE_DELETE, or antivirus/the search indexer) or
// ERROR_SHARING_VIOLATION. Both clear within milliseconds, so the replace is
// worth retrying rather than failing the whole sidecar write (and the audit
// flush). Issue: TestFlushLoop_PeriodicSync Windows flake.
func isTransientReplaceErr(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

func replaceFile(from, to string) error {
	return retryReplace(
		func() error { return moveFileReplace(from, to) },
		isTransientReplaceErr,
		replaceMaxAttempts, replaceBackoff, time.Sleep,
	)
}
