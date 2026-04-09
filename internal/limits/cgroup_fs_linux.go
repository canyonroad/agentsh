//go:build linux

package limits

import (
	"os"
)

// cgroupFile is the write handle returned by cgroupFS.OpenFile.
// It abstracts over *os.File for testing.
type cgroupFile interface {
	WriteString(s string) (int, error)
	Close() error
}

// cgroupFS abstracts filesystem operations on the cgroup hierarchy.
// The real implementation delegates to the os package; tests use fakeCgroupFS.
type cgroupFS interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	Mkdir(path string, perm os.FileMode) error
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
	ReadDir(path string) ([]os.DirEntry, error)
	OpenFile(path string, flag int, perm os.FileMode) (cgroupFile, error)
}

// osCgroupFS is the production cgroupFS backed by the real OS.
type osCgroupFS struct{}

func (osCgroupFS) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (osCgroupFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (osCgroupFS) Mkdir(path string, perm os.FileMode) error {
	return os.Mkdir(path, perm)
}

func (osCgroupFS) Remove(path string) error {
	return os.Remove(path)
}

func (osCgroupFS) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (osCgroupFS) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func (osCgroupFS) OpenFile(path string, flag int, perm os.FileMode) (cgroupFile, error) {
	return os.OpenFile(path, flag, perm)
}
