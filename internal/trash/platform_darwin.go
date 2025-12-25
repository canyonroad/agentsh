//go:build darwin

package trash

import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// capturePlatformMetadata captures macOS-specific metadata.
func capturePlatformMetadata(path string, info os.FileInfo, entry *Entry, cfg Config) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		entry.UID = int(stat.Uid)
		entry.GID = int(stat.Gid)
		entry.MacFlags = stat.Flags
	}

	// Capture extended attributes (common on macOS for things like
	// com.apple.quarantine, com.apple.FinderInfo, etc.)
	if cfg.PreserveXattrs {
		xattrs, err := listXattrs(path)
		if err == nil {
			for _, name := range xattrs {
				value, err := getXattr(path, name)
				if err == nil {
					entry.Xattrs = append(entry.Xattrs, Xattr{
						Name:  name,
						Value: value,
					})
				}
			}
		}
	}

	return nil
}

// restorePlatformMetadata restores macOS-specific metadata.
func restorePlatformMetadata(path string, entry *Entry) error {
	// Restore ownership
	if entry.UID != 0 || entry.GID != 0 {
		if err := os.Lchown(path, entry.UID, entry.GID); err != nil {
			if !os.IsPermission(err) {
				return err
			}
		}
	}

	// Restore macOS file flags (immutable, hidden, etc.)
	if entry.MacFlags != 0 {
		_ = unix.Chflags(path, int(entry.MacFlags))
	}

	// Restore extended attributes
	for _, xattr := range entry.Xattrs {
		_ = setXattr(path, xattr.Name, xattr.Value)
	}

	return nil
}

// listXattrs lists all extended attributes on a file.
func listXattrs(path string) ([]string, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil || size == 0 {
		return nil, err
	}
	buf := make([]byte, size)
	size, err = unix.Llistxattr(path, buf)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, name := range strings.Split(string(buf[:size]), "\x00") {
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// getXattr gets the value of an extended attribute.
func getXattr(path, name string) ([]byte, error) {
	size, err := unix.Lgetxattr(path, name, nil)
	if err != nil || size <= 0 {
		return nil, err
	}
	buf := make([]byte, size)
	_, err = unix.Lgetxattr(path, name, buf)
	return buf, err
}

// setXattr sets an extended attribute.
func setXattr(path, name string, value []byte) error {
	return unix.Lsetxattr(path, name, value, 0)
}
