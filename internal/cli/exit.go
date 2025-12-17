package cli

import "fmt"

// ExitError is returned by commands that want to control the process exit code
// without necessarily printing an additional error message.
type ExitError struct {
	code    int
	message string
}

func (e *ExitError) Error() string {
	if e == nil {
		return ""
	}
	if e.message != "" {
		return e.message
	}
	return fmt.Sprintf("exit %d", e.code)
}

func (e *ExitError) Code() int {
	if e == nil {
		return 1
	}
	return e.code
}

func (e *ExitError) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}
