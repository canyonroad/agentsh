package transport

// State represents one of the four transport state-machine states.
type State int

const (
	StateConnecting State = iota
	StateReplaying
	StateLive
	StateShutdown
)

func (s State) String() string {
	switch s {
	case StateConnecting:
		return "Connecting"
	case StateReplaying:
		return "Replaying"
	case StateLive:
		return "Live"
	case StateShutdown:
		return "Shutdown"
	default:
		return "Unknown"
	}
}
