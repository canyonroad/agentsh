package service

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/agentsh/agentsh/internal/policy"
)

const (
	RuleSourceDBUnavoidability = "db_unavoidability"

	BypassModeTCPDirect       = "tcp_direct"
	BypassModeUnixSocket      = "unix_socket"
	BypassModePortForwardTool = "port_forward_tool"
	BypassModeDNSAlias        = "dns_alias"
	BypassModeCustomTunnel    = "custom_tunnel"
)

var ErrBundleInvalidOptions = errors.New("db unavoidability bundle invalid options")

type IPResolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

type BundleOptions struct {
	SessionID                  string
	ProxySessionID             string
	SocketBaseDir              string
	IncludeToolRules           bool
	Mode                       Unavoidability
	AllowHostnameOnlyInEnforce bool
	Resolver                   IPResolver
}

type BundleWarning struct {
	Code    string
	Service string
	Message string
}

type Bundle struct {
	Policy   policy.Policy
	Metadata []policy.RuleMetadata
	Warnings []BundleWarning
}

func GenerateBundle(cfg Config, opts BundleOptions) (Bundle, error) {
	if err := validateBundleOptions(cfg, opts); err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Policy: policy.Policy{
			Version:     1,
			Name:        "db-unavoidability-" + sanitizeRulePart(opts.SessionID),
			Description: "Generated DB unavoidability bundle for AgentSH session " + opts.SessionID,
		},
	}, nil
}

func validateBundleOptions(cfg Config, opts BundleOptions) error {
	if opts.SessionID == "" {
		return fmt.Errorf("%w: SessionID is required", ErrBundleInvalidOptions)
	}
	if opts.ProxySessionID == "" {
		return fmt.Errorf("%w: ProxySessionID is required", ErrBundleInvalidOptions)
	}
	if opts.Mode != UnavoidabilityObserve && opts.Mode != UnavoidabilityEnforce {
		return fmt.Errorf("%w: Mode must be observe or enforce", ErrBundleInvalidOptions)
	}
	for i, svc := range cfg.Services {
		if svc.Listen.Kind == "tcp" && opts.Mode == UnavoidabilityEnforce {
			return fmt.Errorf("services[%d] %s: tcp listeners are not supported for DB enforce mode in spec section 12.5", i, svc.Name)
		}
	}
	return nil
}

func sanitizeRulePart(s string) string {
	if s == "" {
		return "empty"
	}
	out := make([]byte, 0, len(s))
	lastDash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, c)
			lastDash = false
		case c >= 'A' && c <= 'Z':
			out = append(out, c+'a'-'A')
			lastDash = false
		case c >= '0' && c <= '9':
			out = append(out, c)
			lastDash = false
		default:
			if !lastDash {
				out = append(out, '-')
				lastDash = true
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "empty"
	}
	return string(out)
}
