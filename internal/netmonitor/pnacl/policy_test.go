package pnacl

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileNetworkRule(t *testing.T) {
	tests := []struct {
		name    string
		target  NetworkTarget
		wantErr bool
	}{
		{
			name: "valid hostname",
			target: NetworkTarget{
				Host:     "api.anthropic.com",
				Port:     "443",
				Decision: DecisionAllow,
			},
		},
		{
			name: "valid hostname glob",
			target: NetworkTarget{
				Host:     "*.anthropic.com",
				Port:     "443",
				Protocol: "tcp",
				Decision: DecisionAllow,
			},
		},
		{
			name: "valid IP",
			target: NetworkTarget{
				IP:       "104.18.0.1",
				Port:     "443",
				Decision: DecisionDeny,
			},
		},
		{
			name: "valid CIDR",
			target: NetworkTarget{
				CIDR:     "10.0.0.0/8",
				Decision: DecisionDeny,
			},
		},
		{
			name: "valid port range",
			target: NetworkTarget{
				Host:     "example.com",
				Port:     "8000-9000",
				Decision: DecisionAllow,
			},
		},
		{
			name: "valid wildcard port",
			target: NetworkTarget{
				Host:     "example.com",
				Port:     "*",
				Decision: DecisionAllow,
			},
		},
		{
			name: "valid empty port means any",
			target: NetworkTarget{
				Host:     "example.com",
				Decision: DecisionAllow,
			},
		},
		{
			name: "invalid IP",
			target: NetworkTarget{
				IP:       "not-an-ip",
				Decision: DecisionDeny,
			},
			wantErr: true,
		},
		{
			name: "invalid CIDR",
			target: NetworkTarget{
				CIDR:     "10.0.0.0/99",
				Decision: DecisionDeny,
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			target: NetworkTarget{
				Host:     "example.com",
				Port:     "not-a-port",
				Decision: DecisionAllow,
			},
			wantErr: true,
		},
		{
			name: "invalid port range reversed",
			target: NetworkTarget{
				Host:     "example.com",
				Port:     "9000-8000",
				Decision: DecisionAllow,
			},
			wantErr: true,
		},
		{
			name: "invalid port out of range",
			target: NetworkTarget{
				Host:     "example.com",
				Port:     "70000",
				Decision: DecisionAllow,
			},
			wantErr: true,
		},
		{
			name: "invalid host glob",
			target: NetworkTarget{
				Host:     "[invalid",
				Decision: DecisionAllow,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := CompileNetworkRule(tt.target)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, rule)
			assert.Equal(t, tt.target.Decision, rule.Decision())
		})
	}
}

func TestNetworkRule_Matches(t *testing.T) {
	tests := []struct {
		name     string
		target   NetworkTarget
		host     string
		ip       net.IP
		port     int
		protocol string
		want     bool
	}{
		{
			name: "match hostname exactly",
			target: NetworkTarget{
				Host:     "api.anthropic.com",
				Port:     "443",
				Decision: DecisionAllow,
			},
			host:     "api.anthropic.com",
			port:     443,
			protocol: "tcp",
			want:     true,
		},
		{
			name: "match hostname glob",
			target: NetworkTarget{
				Host:     "*.anthropic.com",
				Decision: DecisionAllow,
			},
			host: "api.anthropic.com",
			port: 443,
			want: true,
		},
		{
			name: "match hostname glob single subdomain",
			target: NetworkTarget{
				Host:     "*.anthropic.com",
				Decision: DecisionAllow,
			},
			host: "staging.anthropic.com",
			port: 443,
			want: true,
		},
		{
			name: "no match hostname glob multi-level subdomain",
			target: NetworkTarget{
				Host:     "*.anthropic.com",
				Decision: DecisionAllow,
			},
			host: "staging.api.anthropic.com",
			port: 443,
			want: false, // * matches single segment only
		},
		{
			name: "no match hostname glob",
			target: NetworkTarget{
				Host:     "*.anthropic.com",
				Decision: DecisionAllow,
			},
			host: "api.example.com",
			port: 443,
			want: false,
		},
		{
			name: "no match wrong port",
			target: NetworkTarget{
				Host:     "api.anthropic.com",
				Port:     "443",
				Decision: DecisionAllow,
			},
			host: "api.anthropic.com",
			port: 80,
			want: false,
		},
		{
			name: "match port range",
			target: NetworkTarget{
				Host:     "example.com",
				Port:     "8000-9000",
				Decision: DecisionAllow,
			},
			host: "example.com",
			port: 8500,
			want: true,
		},
		{
			name: "no match port outside range",
			target: NetworkTarget{
				Host:     "example.com",
				Port:     "8000-9000",
				Decision: DecisionAllow,
			},
			host: "example.com",
			port: 7999,
			want: false,
		},
		{
			name: "match specific IP",
			target: NetworkTarget{
				IP:       "104.18.0.1",
				Decision: DecisionDeny,
			},
			host: "",
			ip:   net.ParseIP("104.18.0.1"),
			port: 443,
			want: true,
		},
		{
			name: "no match different IP",
			target: NetworkTarget{
				IP:       "104.18.0.1",
				Decision: DecisionDeny,
			},
			ip:   net.ParseIP("104.18.0.2"),
			port: 443,
			want: false,
		},
		{
			name: "match CIDR",
			target: NetworkTarget{
				CIDR:     "10.0.0.0/8",
				Decision: DecisionDeny,
			},
			ip:   net.ParseIP("10.1.2.3"),
			port: 80,
			want: true,
		},
		{
			name: "no match CIDR",
			target: NetworkTarget{
				CIDR:     "10.0.0.0/8",
				Decision: DecisionDeny,
			},
			ip:   net.ParseIP("192.168.1.1"),
			port: 80,
			want: false,
		},
		{
			name: "match protocol tcp",
			target: NetworkTarget{
				Host:     "example.com",
				Protocol: "tcp",
				Decision: DecisionAllow,
			},
			host:     "example.com",
			port:     443,
			protocol: "tcp",
			want:     true,
		},
		{
			name: "no match wrong protocol",
			target: NetworkTarget{
				Host:     "example.com",
				Protocol: "tcp",
				Decision: DecisionAllow,
			},
			host:     "example.com",
			port:     53,
			protocol: "udp",
			want:     false,
		},
		{
			name: "wildcard protocol matches any",
			target: NetworkTarget{
				Host:     "example.com",
				Protocol: "*",
				Decision: DecisionAllow,
			},
			host:     "example.com",
			port:     53,
			protocol: "udp",
			want:     true,
		},
		{
			name: "empty protocol matches any",
			target: NetworkTarget{
				Host:     "example.com",
				Decision: DecisionAllow,
			},
			host:     "example.com",
			port:     53,
			protocol: "udp",
			want:     true,
		},
		{
			name: "case insensitive hostname",
			target: NetworkTarget{
				Host:     "API.Anthropic.COM",
				Decision: DecisionAllow,
			},
			host: "api.anthropic.com",
			port: 443,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := CompileNetworkRule(tt.target)
			require.NoError(t, err)

			got := rule.Matches(tt.host, tt.ip, tt.port, tt.protocol)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPolicyEngine_Evaluate(t *testing.T) {
	config := &Config{
		Default: "deny",
		Processes: []ProcessConfig{
			{
				Name: "claude-code",
				Match: ProcessMatchCriteria{
					ProcessName: "claude-code",
				},
				Default: "approve",
				Rules: []NetworkTarget{
					{
						Host:     "api.anthropic.com",
						Port:     "443",
						Protocol: "tcp",
						Decision: DecisionAllow,
					},
					{
						Host:     "*.anthropic.com",
						Port:     "443",
						Decision: DecisionAllow,
					},
					{
						CIDR:     "10.0.0.0/8",
						Decision: DecisionDeny,
					},
				},
			},
		},
	}

	engine, err := NewPolicyEngine(config)
	require.NoError(t, err)

	tests := []struct {
		name         string
		proc         ProcessInfo
		host         string
		ip           net.IP
		port         int
		protocol     string
		wantDecision Decision
		wantRule     int
	}{
		{
			name: "allow api.anthropic.com",
			proc: ProcessInfo{
				Name: "claude-code",
			},
			host:         "api.anthropic.com",
			port:         443,
			protocol:     "tcp",
			wantDecision: DecisionAllow,
			wantRule:     0,
		},
		{
			name: "allow wildcard anthropic",
			proc: ProcessInfo{
				Name: "claude-code",
			},
			host:         "staging.anthropic.com",
			port:         443,
			protocol:     "tcp",
			wantDecision: DecisionAllow,
			wantRule:     1,
		},
		{
			name: "deny private network",
			proc: ProcessInfo{
				Name: "claude-code",
			},
			ip:           net.ParseIP("10.1.2.3"),
			port:         80,
			protocol:     "tcp",
			wantDecision: DecisionDeny,
			wantRule:     2,
		},
		{
			name: "default approve for unmatched",
			proc: ProcessInfo{
				Name: "claude-code",
			},
			host:         "unknown.example.com",
			port:         443,
			protocol:     "tcp",
			wantDecision: DecisionApprove,
			wantRule:     -1,
		},
		{
			name: "unknown process uses global default",
			proc: ProcessInfo{
				Name: "other-process",
			},
			host:         "example.com",
			port:         443,
			protocol:     "tcp",
			wantDecision: DecisionDeny,
			wantRule:     -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.proc, tt.host, tt.ip, tt.port, tt.protocol)
			assert.Equal(t, tt.wantDecision, result.Decision)
			assert.Equal(t, tt.wantRule, result.RuleIndex)
		})
	}
}

func TestPolicyEngine_ChildInheritance(t *testing.T) {
	config := &Config{
		Default: "deny",
		Processes: []ProcessConfig{
			{
				Name: "claude-code",
				Match: ProcessMatchCriteria{
					ProcessName: "claude-code",
				},
				Default: "approve",
				Rules: []NetworkTarget{
					{
						Host:     "api.anthropic.com",
						Port:     "443",
						Decision: DecisionAllow,
					},
				},
				Children: []ChildConfig{
					{
						Name: "curl",
						Match: ProcessMatchCriteria{
							ProcessName: "curl",
						},
						Inherit: true,
						Rules: []NetworkTarget{
							{
								Host:     "pypi.org",
								Port:     "443",
								Decision: DecisionAllow,
							},
						},
					},
					{
						Name: "wget",
						Match: ProcessMatchCriteria{
							ProcessName: "wget",
						},
						Inherit: false,
						Rules: []NetworkTarget{
							{
								Host:     "files.example.com",
								Decision: DecisionAllow,
							},
						},
					},
				},
			},
		},
	}

	engine, err := NewPolicyEngine(config)
	require.NoError(t, err)

	// Parent process info for all tests.
	parent := ProcessInfo{Name: "claude-code"}

	tests := []struct {
		name         string
		child        ProcessInfo
		host         string
		port         int
		wantDecision Decision
		wantChild    string
		isInherited  bool
	}{
		{
			name: "child specific rule matches",
			child: ProcessInfo{
				Name: "curl",
			},
			host:         "pypi.org",
			port:         443,
			wantDecision: DecisionAllow,
			wantChild:    "curl",
			isInherited:  false,
		},
		{
			name: "child inherits parent rule",
			child: ProcessInfo{
				Name: "curl",
			},
			host:         "api.anthropic.com",
			port:         443,
			wantDecision: DecisionAllow,
			wantChild:    "curl",
			isInherited:  true,
		},
		{
			name: "child without inheritance uses parent default",
			child: ProcessInfo{
				Name: "wget",
			},
			host:         "api.anthropic.com",
			port:         443,
			wantDecision: DecisionApprove, // Parent default, not inherited rule.
			wantChild:    "wget",
			isInherited:  false,
		},
		{
			name: "child without inheritance own rule",
			child: ProcessInfo{
				Name: "wget",
			},
			host:         "files.example.com",
			port:         443,
			wantDecision: DecisionAllow,
			wantChild:    "wget",
			isInherited:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use EvaluateForParentChild which knows the parent-child relationship.
			result := engine.EvaluateForParentChild(parent, tt.child, tt.host, nil, tt.port, "tcp")
			assert.Equal(t, tt.wantDecision, result.Decision)
			assert.Equal(t, tt.wantChild, result.ChildName)
			assert.Equal(t, tt.isInherited, result.IsInherited)
		})
	}
}

func TestPolicyEngine_EvaluateForParentChild(t *testing.T) {
	config := &Config{
		Default: "deny",
		Processes: []ProcessConfig{
			{
				Name: "claude-code",
				Match: ProcessMatchCriteria{
					ProcessName: "claude-code",
				},
				Default: "approve",
				Rules: []NetworkTarget{
					{
						Host:     "api.anthropic.com",
						Port:     "443",
						Decision: DecisionAllow,
					},
				},
				Children: []ChildConfig{
					{
						Name: "curl",
						Match: ProcessMatchCriteria{
							ProcessName: "curl",
						},
						Inherit: true,
						Rules: []NetworkTarget{
							{
								Host:     "pypi.org",
								Port:     "443",
								Decision: DecisionAllow,
							},
						},
					},
				},
			},
		},
	}

	engine, err := NewPolicyEngine(config)
	require.NoError(t, err)

	parent := ProcessInfo{Name: "claude-code"}
	child := ProcessInfo{Name: "curl"}

	// Child-specific rule.
	result := engine.EvaluateForParentChild(parent, child, "pypi.org", nil, 443, "tcp")
	assert.Equal(t, DecisionAllow, result.Decision)
	assert.Equal(t, "curl", result.ChildName)

	// Inherited parent rule.
	result = engine.EvaluateForParentChild(parent, child, "api.anthropic.com", nil, 443, "tcp")
	assert.Equal(t, DecisionAllow, result.Decision)
	assert.True(t, result.IsInherited)

	// Unknown child falls back to parent rules.
	unknownChild := ProcessInfo{Name: "unknown"}
	result = engine.EvaluateForParentChild(parent, unknownChild, "api.anthropic.com", nil, 443, "tcp")
	assert.Equal(t, DecisionAllow, result.Decision)
}

func TestDecisionTypes(t *testing.T) {
	tests := []struct {
		decision Decision
		valid    bool
	}{
		{DecisionAllow, true},
		{DecisionDeny, true},
		{DecisionApprove, true},
		{DecisionAllowOnceThenApprove, true},
		{DecisionAudit, true},
		{Decision("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			valid := isValidDecision(string(tt.decision))
			assert.Equal(t, tt.valid, valid)
		})
	}
}

func TestNetworkRule_Target(t *testing.T) {
	target := NetworkTarget{
		Host:     "example.com",
		Port:     "443",
		Protocol: "tcp",
		Decision: DecisionAllow,
	}

	rule, err := CompileNetworkRule(target)
	require.NoError(t, err)

	got := rule.Target()
	assert.Equal(t, target.Host, got.Host)
	assert.Equal(t, target.Port, got.Port)
	assert.Equal(t, target.Protocol, got.Protocol)
	assert.Equal(t, target.Decision, got.Decision)
}
