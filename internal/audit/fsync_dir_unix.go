//go:build unix

package audit

import "os"

func syncDir(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}
