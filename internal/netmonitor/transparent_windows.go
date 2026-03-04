//go:build windows

package netmonitor

import "strings"

var platformTransparentCommands = map[string]bool{
	"cmd.exe":        true,
	"powershell.exe": true,
	"pwsh.exe":       true,
	"wsl.exe":        true,
}

func isPlatformTransparentCommand(basename string) bool {
	return platformTransparentCommands[strings.ToLower(basename)]
}
