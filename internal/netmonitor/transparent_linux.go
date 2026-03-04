//go:build linux

package netmonitor

import "strings"

var platformTransparentCommands = map[string]bool{
	"busybox": true,
	"doas":    true,
	"strace":  true,
	"ltrace":  true,
}

func isPlatformTransparentCommand(basename string) bool {
	if platformTransparentCommands[basename] {
		return true
	}
	if strings.HasPrefix(basename, "ld-linux") {
		return true
	}
	return false
}
