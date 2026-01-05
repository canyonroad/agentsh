//go:build linux && cgo

package seccomp

import (
	"fmt"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// ResolveSyscall converts a syscall name to its number for the current arch.
func ResolveSyscall(name string) (int, error) {
	nr, err := libseccomp.GetSyscallFromName(name)
	if err != nil {
		return 0, fmt.Errorf("unknown syscall %q: %w", name, err)
	}
	return int(nr), nil
}

// ResolveSyscalls converts syscall names to numbers, skipping unknown ones.
func ResolveSyscalls(names []string) ([]int, []string) {
	var numbers []int
	var skipped []string
	for _, name := range names {
		nr, err := ResolveSyscall(name)
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		numbers = append(numbers, nr)
	}
	return numbers, skipped
}
