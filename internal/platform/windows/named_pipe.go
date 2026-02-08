package windows

import "fmt"

// GenerateWrapPipeName returns the named pipe path for wrap CLI<->server communication.
func GenerateWrapPipeName(sessionID string) string {
	return fmt.Sprintf(`\\.\pipe\agentsh-wrap-%s`, sessionID)
}

// GenerateStubPipeName returns the named pipe path for stub<->server communication.
func GenerateStubPipeName(sessionID string, pid uint32) string {
	return fmt.Sprintf(`\\.\pipe\agentsh-stub-%s-%d`, sessionID, pid)
}

// PipeSecuritySDDL returns an SDDL string granting access to:
//   - SY: Local System
//   - BA: Built-in Administrators
//   - CO: Creator Owner
func PipeSecuritySDDL() string {
	return "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;CO)"
}
