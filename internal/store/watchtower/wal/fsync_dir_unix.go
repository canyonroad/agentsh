//go:build unix

package wal

import "os"

// syncDir opens path and calls Sync() on it. On unix this fsyncs the
// directory entry, which is what makes a rename or create durable across
// crashes. Spec §"Lifecycle".
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// atomicRename renames from→to atomically. On unix, os.Rename is already
// atomic on the same filesystem, which is the only case we use it for.
func atomicRename(from, to string) error {
	return os.Rename(from, to)
}
