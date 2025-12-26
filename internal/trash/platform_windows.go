//go:build windows

package trash

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// capturePlatformMetadata captures Windows-specific metadata.
func capturePlatformMetadata(path string, info os.FileInfo, entry *Entry, cfg Config) error {
	// Get Windows file attributes
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	attrs, err := syscall.GetFileAttributes(pathPtr)
	if err == nil {
		entry.WinAttrs = attrs
	}

	// Capture security descriptor if requested
	if cfg.PreserveSecurity {
		sd, err := getSecurityDescriptor(path)
		if err == nil {
			entry.WinSecurity = sd
		}
	}

	return nil
}

// restorePlatformMetadata restores Windows-specific metadata.
func restorePlatformMetadata(path string, entry *Entry) error {
	// Restore Windows file attributes
	if entry.WinAttrs != 0 {
		pathPtr, err := syscall.UTF16PtrFromString(path)
		if err == nil {
			_ = syscall.SetFileAttributes(pathPtr, entry.WinAttrs)
		}
	}

	// Restore security descriptor
	if len(entry.WinSecurity) > 0 {
		_ = setSecurityDescriptor(path, entry.WinSecurity)
	}

	return nil
}

// getSecurityDescriptor retrieves the security descriptor for a file.
func getSecurityDescriptor(path string) ([]byte, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if sd != nil {
			_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(sd)))
		}
	}()

	length := sd.Length()
	buf := make([]byte, length)
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(sd)), length))
	return buf, nil
}

// setSecurityDescriptor sets the security descriptor for a file.
func setSecurityDescriptor(path string, sdBytes []byte) error {
	if len(sdBytes) == 0 {
		return nil
	}

	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&sdBytes[0]))

	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil,
		dacl,
		nil,
	)
}
