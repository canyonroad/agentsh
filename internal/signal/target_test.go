//go:build !windows

// internal/signal/target_test.go
package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTargetType(t *testing.T) {
	assert.Equal(t, "self", string(TargetSelf))
	assert.Equal(t, "children", string(TargetChildren))
	assert.Equal(t, "external", string(TargetExternal))
	assert.Equal(t, "system", string(TargetSystem))
}

func TestParseTargetSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     TargetSpec
		wantType TargetType
		wantErr  bool
	}{
		{"simple type", TargetSpec{Type: "self"}, TargetSelf, false},
		{"children", TargetSpec{Type: "children"}, TargetChildren, false},
		{"invalid", TargetSpec{Type: "invalid"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseTargetSpec(tt.spec)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantType, parsed.Type)
			}
		})
	}
}

func TestParseTargetSpecAllTypes(t *testing.T) {
	validTypes := []string{
		"self", "children", "descendants", "siblings", "session",
		"parent", "external", "system", "user", "process", "pid_range",
	}
	for _, typeStr := range validTypes {
		t.Run(typeStr, func(t *testing.T) {
			spec := TargetSpec{Type: typeStr}
			if typeStr == "pid_range" {
				spec.Min = 100
				spec.Max = 200
			}
			parsed, err := ParseTargetSpec(spec)
			assert.NoError(t, err)
			assert.Equal(t, TargetType(typeStr), parsed.Type)
		})
	}
}

func TestParseTargetSpecProcess(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		match   string
		noMatch string
		wantErr bool
	}{
		{"simple glob", "nginx*", "nginx-worker", "apache", false},
		{"exact match", "sshd", "sshd", "ssh", false},
		{"wildcard", "*daemon*", "mydaemon", "myservice", false},
		{"invalid glob", "[", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := TargetSpec{Type: "process", Pattern: tt.pattern}
			parsed, err := ParseTargetSpec(spec)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, parsed.ProcessGlob)
				assert.True(t, parsed.ProcessGlob.Match(tt.match))
				assert.False(t, parsed.ProcessGlob.Match(tt.noMatch))
			}
		})
	}
}

func TestParseTargetSpecPIDRange(t *testing.T) {
	tests := []struct {
		name    string
		min     int
		max     int
		wantErr bool
	}{
		{"valid range", 100, 200, false},
		{"single pid range", 1000, 1000, false},
		{"zero min", 0, 100, true},
		{"zero max", 100, 0, true},
		{"negative min", -1, 100, true},
		{"min > max", 200, 100, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := TargetSpec{Type: "pid_range", Min: tt.min, Max: tt.max}
			parsed, err := ParseTargetSpec(spec)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.min, parsed.PIDMin)
				assert.Equal(t, tt.max, parsed.PIDMax)
			}
		})
	}
}

func TestMatchesSelf(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetSelf}

	// Same PID should match
	ctx := &TargetContext{SourcePID: 1000, TargetPID: 1000}
	assert.True(t, parsed.Matches(ctx))

	// Different PID should not match
	ctx = &TargetContext{SourcePID: 1000, TargetPID: 2000}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesChildren(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetChildren}

	// Child process should match
	ctx := &TargetContext{IsChild: true}
	assert.True(t, parsed.Matches(ctx))

	// Non-child should not match
	ctx = &TargetContext{IsChild: false}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesDescendants(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetDescendants}

	ctx := &TargetContext{IsDescendant: true}
	assert.True(t, parsed.Matches(ctx))

	ctx = &TargetContext{IsDescendant: false}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesSiblings(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetSiblings}

	ctx := &TargetContext{IsSibling: true}
	assert.True(t, parsed.Matches(ctx))

	ctx = &TargetContext{IsSibling: false}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesSession(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetSession}

	ctx := &TargetContext{InSession: true}
	assert.True(t, parsed.Matches(ctx))

	ctx = &TargetContext{InSession: false}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesParent(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetParent}

	ctx := &TargetContext{IsParent: true}
	assert.True(t, parsed.Matches(ctx))

	ctx = &TargetContext{IsParent: false}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesExternal(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetExternal}

	// Not in session = external
	ctx := &TargetContext{InSession: false}
	assert.True(t, parsed.Matches(ctx))

	// In session = not external
	ctx = &TargetContext{InSession: true}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesSystem(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetSystem}

	tests := []struct {
		pid   int
		match bool
	}{
		{1, true},    // init
		{2, true},    // kthreadd
		{50, false},  // not system (could be normal process in container)
		{99, false},  // not system
		{100, false}, // not system
		{1000, false},
	}
	for _, tt := range tests {
		ctx := &TargetContext{TargetPID: tt.pid}
		assert.Equal(t, tt.match, parsed.Matches(ctx), "PID %d", tt.pid)
	}
}

func TestMatchesUser(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetUser}

	// Same user but not in session
	ctx := &TargetContext{SameUser: true, InSession: false}
	assert.True(t, parsed.Matches(ctx))

	// Same user in session
	ctx = &TargetContext{SameUser: true, InSession: true}
	assert.False(t, parsed.Matches(ctx))

	// Different user
	ctx = &TargetContext{SameUser: false, InSession: false}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesProcess(t *testing.T) {
	spec := TargetSpec{Type: "process", Pattern: "nginx*"}
	parsed, err := ParseTargetSpec(spec)
	assert.NoError(t, err)

	// Match nginx processes
	ctx := &TargetContext{TargetCmd: "nginx-worker"}
	assert.True(t, parsed.Matches(ctx))

	ctx = &TargetContext{TargetCmd: "nginx"}
	assert.True(t, parsed.Matches(ctx))

	// Don't match other processes
	ctx = &TargetContext{TargetCmd: "apache"}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesProcessNoGlob(t *testing.T) {
	// Process target without glob should not match anything
	parsed := &ParsedTarget{Type: TargetProcess, ProcessGlob: nil}
	ctx := &TargetContext{TargetCmd: "anything"}
	assert.False(t, parsed.Matches(ctx))
}

func TestMatchesPIDRange(t *testing.T) {
	parsed := &ParsedTarget{Type: TargetPIDRange, PIDMin: 100, PIDMax: 200}

	tests := []struct {
		pid   int
		match bool
	}{
		{99, false},  // below range
		{100, true},  // lower bound
		{150, true},  // middle
		{200, true},  // upper bound
		{201, false}, // above range
	}
	for _, tt := range tests {
		ctx := &TargetContext{TargetPID: tt.pid}
		assert.Equal(t, tt.match, parsed.Matches(ctx), "PID %d", tt.pid)
	}
}

func TestMatchesUnknownType(t *testing.T) {
	// Unknown type should not match anything
	parsed := &ParsedTarget{Type: TargetType("unknown")}
	ctx := &TargetContext{
		SourcePID:    1000,
		TargetPID:    1000,
		IsChild:      true,
		IsDescendant: true,
		InSession:    true,
	}
	assert.False(t, parsed.Matches(ctx))
}

func TestParseCaseInsensitive(t *testing.T) {
	tests := []struct {
		input    string
		expected TargetType
	}{
		{"SELF", TargetSelf},
		{"Self", TargetSelf},
		{"CHILDREN", TargetChildren},
		{"  external  ", TargetExternal},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed, err := ParseTargetSpec(TargetSpec{Type: tt.input})
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, parsed.Type)
		})
	}
}

func TestTargetSystemMatching(t *testing.T) {
	target := &ParsedTarget{Type: TargetSystem}

	// PID 1 (init) should match
	ctx := &TargetContext{TargetPID: 1}
	assert.True(t, target.Matches(ctx), "PID 1 should match TargetSystem")

	// PID 2 (kthreadd on Linux) should match
	ctx = &TargetContext{TargetPID: 2}
	assert.True(t, target.Matches(ctx), "PID 2 should match TargetSystem")

	// Low PID like 50 should NOT match (could be normal process in container)
	ctx = &TargetContext{TargetPID: 50}
	assert.False(t, target.Matches(ctx), "PID 50 should NOT match TargetSystem")

	// Normal PID should NOT match
	ctx = &TargetContext{TargetPID: 1234}
	assert.False(t, target.Matches(ctx), "PID 1234 should NOT match TargetSystem")
}
