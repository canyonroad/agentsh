package jsonl

import "errors"

var ErrLocked = errors.New("jsonl lock held")

func lockPath(path string) string {
	return path + ".lock"
}
