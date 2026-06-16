package decisionctx

import (
	"context"
	"encoding/json"
	"strconv"
)

// tailscaleStatusFunc returns the local node's login name from tailscaled.
// available=false means tailscaled is not running / not reachable; that is
// not an error condition for resolution.
type tailscaleStatusFunc func(ctx context.Context, socket string) (login string, available bool, err error)

// tailscaleSource overrides the User slot with the local Tailscale
// identity when tailscaled is up.
type tailscaleSource struct {
	socket string
	status tailscaleStatusFunc
}

func newTailscaleSource(socket string, status tailscaleStatusFunc) tailscaleSource {
	return tailscaleSource{socket: socket, status: status}
}

func (tailscaleSource) Name() string { return "tailscale" }

func (s tailscaleSource) Resolve(ctx context.Context, into *DecisionContext) error {
	login, ok, _ := s.status(ctx, s.socket) // unavailability is not fatal
	if ok && login != "" {
		into.User = User{Value: login, Source: SourceTailscale}
	}
	return nil
}

// parseTailscaleStatus extracts the local node login from a tailscaled
// /localapi/v0/status JSON body. Platform-neutral so it is testable
// everywhere.
func parseTailscaleStatus(body []byte) (string, bool) {
	var st struct {
		Self *struct {
			UserID int64 `json:"UserID"`
		} `json:"Self"`
		User map[string]struct {
			LoginName string `json:"LoginName"`
		} `json:"User"`
	}
	if err := json.Unmarshal(body, &st); err != nil || st.Self == nil {
		return "", false
	}
	u, ok := st.User[strconv.FormatInt(st.Self.UserID, 10)]
	if !ok || u.LoginName == "" {
		return "", false
	}
	return u.LoginName, true
}
