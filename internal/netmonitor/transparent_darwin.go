//go:build darwin

package netmonitor

var platformTransparentCommands = map[string]bool{}

func isPlatformTransparentCommand(basename string) bool {
	return platformTransparentCommands[basename]
}
