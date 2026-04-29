package skillcheck

import "os"

func readDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}
