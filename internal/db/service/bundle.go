package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

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

const dnsResolutionTimeout = 2 * time.Second

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
	b := Bundle{
		Policy: policy.Policy{
			Version:     1,
			Name:        "db-unavoidability-" + sanitizeRulePart(opts.SessionID),
			Description: "Generated DB unavoidability bundle for AgentSH session " + opts.SessionID,
		},
	}
	serviceParts := serviceRuleParts(cfg.Services)
	for i, svc := range cfg.Services {
		addCoreServiceRules(&b, svc, serviceParts[i])
		if err := addResolvedIPRules(context.Background(), &b, svc, serviceParts[i], opts); err != nil {
			return Bundle{}, err
		}
	}
	b.Policy.Metadata = append([]policy.RuleMetadata(nil), b.Metadata...)
	return b, nil
}

func addCoreServiceRules(b *Bundle, svc Service, servicePart string) {
	destination := serviceDestination(svc)
	redirectName := "db-" + servicePart + "-redirect"
	networkName := "db-" + servicePart + "-deny-direct"
	unixName := "db-" + servicePart + "-deny-local-postgres-sockets"

	b.Policy.ConnectRedirectRules = append(b.Policy.ConnectRedirectRules, policy.ConnectRedirectRule{
		Name:           redirectName,
		Match:          "^" + regexp.QuoteMeta(destination) + "$",
		RedirectToUnix: svc.Listen.Path,
		Visibility:     "audit_only",
		OnFailure:      "fail_closed",
		Message:        "Routed through AgentSH DB proxy",
	})
	addMetadata(b, redirectName, svc.Name, BypassModeTCPDirect, destination)

	b.Policy.NetworkRules = append(b.Policy.NetworkRules, policy.NetworkRule{
		Name:        networkName,
		Description: "Deny direct DB egress; traffic must use AgentSH DB proxy",
		Domains:     []string{strings.ToLower(svc.Upstream.Host)},
		Ports:       []int{svc.Upstream.Port},
		Decision:    "deny",
		Message:     "Direct database egress is blocked; use the AgentSH DB proxy",
	})
	addMetadata(b, networkName, svc.Name, BypassModeTCPDirect, destination)

	b.Policy.UnixRules = append(b.Policy.UnixRules, policy.UnixSocketRule{
		Name:        unixName,
		Description: "Deny direct local Postgres Unix socket access for DB unavoidability",
		Paths: []string{
			"/var/run/postgresql/.s.PGSQL.*",
			"/tmp/.s.PGSQL.*",
		},
		Operations: []string{"connect"},
		Decision:   "deny",
		Message:    "Direct local database socket access is blocked; use the AgentSH DB proxy",
	})
	addMetadata(b, unixName, svc.Name, BypassModeUnixSocket, "postgres-local-sockets")
}

func addResolvedIPRules(ctx context.Context, b *Bundle, svc Service, servicePart string, opts BundleOptions) error {
	if opts.Resolver == nil {
		return nil
	}
	if net.ParseIP(svc.Upstream.Host) != nil {
		return nil
	}

	resolveCtx, cancel := context.WithTimeout(ctx, dnsResolutionTimeout)
	defer cancel()

	ips, err := opts.Resolver.LookupIP(resolveCtx, svc.Upstream.Host)
	if err != nil {
		warning := BundleWarning{
			Code:    "DNS_EXPANSION_FAILED",
			Service: svc.Name,
			Message: "could not resolve " + svc.Upstream.Host + ": " + err.Error(),
		}
		b.Warnings = append(b.Warnings, warning)
		if opts.Mode == UnavoidabilityEnforce && !opts.AllowHostnameOnlyInEnforce {
			return fmt.Errorf("%w: %s", ErrBundleInvalidOptions, warning.Message)
		}
		return nil
	}

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		ipString := canonicalIPString(ip)
		name := "db-" + servicePart + "-deny-ip-" + sanitizeRulePart(ipString)
		destination := net.JoinHostPort(ipString, strconv.Itoa(svc.Upstream.Port))
		b.Policy.NetworkRules = append(b.Policy.NetworkRules, policy.NetworkRule{
			Name:        name,
			Description: "Deny direct DB egress to resolved upstream IP",
			CIDRs:       []string{ipCIDR(ip)},
			Ports:       []int{svc.Upstream.Port},
			Decision:    "deny",
			Message:     "Direct database egress is blocked; use the AgentSH DB proxy",
		})
		addMetadata(b, name, svc.Name, BypassModeDNSAlias, destination)
	}
	return nil
}

func canonicalIPString(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func ipCIDR(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32"
	}
	return ip.String() + "/128"
}

func addMetadata(b *Bundle, ruleName, serviceName, bypassMode, destination string) {
	b.Metadata = append(b.Metadata, policy.RuleMetadata{
		RuleName:    ruleName,
		Source:      RuleSourceDBUnavoidability,
		DBService:   serviceName,
		BypassMode:  bypassMode,
		Destination: destination,
	})
}

func serviceDestination(svc Service) string {
	return net.JoinHostPort(strings.ToLower(svc.Upstream.Host), strconv.Itoa(svc.Upstream.Port))
}

func serviceRuleParts(services []Service) []string {
	bases := make([]string, len(services))
	counts := make(map[string]int, len(services))
	for i, svc := range services {
		base := sanitizeRulePart(svc.Name)
		bases[i] = base
		counts[base]++
	}

	parts := make([]string, len(services))
	for i, svc := range services {
		part := bases[i]
		if counts[part] > 1 {
			part += "-" + ruleNameHash(svc.Name)
		}
		parts[i] = part
	}
	return parts
}

func ruleNameHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
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
