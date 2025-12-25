package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestPathRedirector_Redirect(t *testing.T) {
	rules := []PathRedirectRule{
		{
			Name:          "redirect-home",
			SourcePattern: "/home/**",
			TargetBase:    "/workspace/.scratch",
			Operations:    []string{"write", "create"},
			PreserveTree:  true,
		},
		{
			Name:          "redirect-tmp",
			SourcePattern: "/tmp/**",
			TargetBase:    "/workspace/.tmp",
			Operations:    []string{"*"},
			PreserveTree:  false,
		},
	}

	pr, err := NewPathRedirector(rules)
	if err != nil {
		t.Fatalf("NewPathRedirector: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		operation  string
		wantPath   string
		wantRedirect bool
	}{
		{
			name:         "redirect home write with tree",
			path:         "/home/user/file.txt",
			operation:    "write",
			wantPath:     "/workspace/.scratch/home/user/file.txt",
			wantRedirect: true,
		},
		{
			name:         "redirect home create with tree",
			path:         "/home/user/subdir/file.txt",
			operation:    "create",
			wantPath:     "/workspace/.scratch/home/user/subdir/file.txt",
			wantRedirect: true,
		},
		{
			name:         "no redirect home read",
			path:         "/home/user/file.txt",
			operation:    "read",
			wantPath:     "/home/user/file.txt",
			wantRedirect: false,
		},
		{
			name:         "redirect tmp without tree",
			path:         "/tmp/foo/bar/file.txt",
			operation:    "write",
			wantPath:     "/workspace/.tmp/file.txt",
			wantRedirect: true,
		},
		{
			name:         "no redirect unmatched path",
			path:         "/var/log/syslog",
			operation:    "write",
			wantPath:     "/var/log/syslog",
			wantRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotRedirect := pr.Redirect(tt.path, tt.operation)
			if gotPath != tt.wantPath {
				t.Errorf("Redirect() path = %q, want %q", gotPath, tt.wantPath)
			}
			if gotRedirect != tt.wantRedirect {
				t.Errorf("Redirect() redirected = %v, want %v", gotRedirect, tt.wantRedirect)
			}
		})
	}
}

func TestPathRedirector_RedirectWithInfo(t *testing.T) {
	rules := []PathRedirectRule{
		{
			Name:          "redirect-home",
			SourcePattern: "/home/**",
			TargetBase:    "/workspace/.scratch",
			Operations:    []string{"write"},
			PreserveTree:  true,
		},
	}

	pr, err := NewPathRedirector(rules)
	if err != nil {
		t.Fatalf("NewPathRedirector: %v", err)
	}

	// Test redirect
	info := pr.RedirectWithInfo("/home/user/file.txt", "write")
	if info == nil {
		t.Fatal("expected redirect info, got nil")
	}
	if info.OriginalPath != "/home/user/file.txt" {
		t.Errorf("OriginalPath = %q, want %q", info.OriginalPath, "/home/user/file.txt")
	}
	if info.RedirectPath != "/workspace/.scratch/home/user/file.txt" {
		t.Errorf("RedirectPath = %q, want %q", info.RedirectPath, "/workspace/.scratch/home/user/file.txt")
	}
	if info.Operation != "write" {
		t.Errorf("Operation = %q, want %q", info.Operation, "write")
	}

	// Test no redirect
	info = pr.RedirectWithInfo("/home/user/file.txt", "read")
	if info != nil {
		t.Errorf("expected nil for read operation, got %+v", info)
	}
}

func TestPathRedirector_Nil(t *testing.T) {
	var pr *PathRedirector
	path, redirected := pr.Redirect("/home/user/file.txt", "write")
	if redirected {
		t.Error("nil PathRedirector should not redirect")
	}
	if path != "/home/user/file.txt" {
		t.Errorf("path = %q, want original", path)
	}
}

func TestCheckFile_WithRedirect(t *testing.T) {
	policy := &Policy{
		Version: 1,
		Name:    "test",
		FileRules: []FileRule{
			{
				Name:         "redirect-home-writes",
				Paths:        []string{"/home/**"},
				Operations:   []string{"write", "create"},
				Decision:     "redirect",
				Message:      "Writes outside workspace redirected",
				RedirectTo:   "/workspace/.scratch",
				PreserveTree: true,
			},
			{
				Name:       "allow-workspace",
				Paths:      []string{"/workspace/**"},
				Operations: []string{"*"},
				Decision:   "allow",
			},
		},
	}

	engine, err := NewEngine(policy, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Test redirect
	dec := engine.CheckFile("/home/user/file.txt", "write")
	if dec.PolicyDecision != types.DecisionRedirect {
		t.Errorf("PolicyDecision = %q, want redirect", dec.PolicyDecision)
	}
	if dec.FileRedirect == nil {
		t.Fatal("expected FileRedirect, got nil")
	}
	if dec.FileRedirect.RedirectPath != "/workspace/.scratch/home/user/file.txt" {
		t.Errorf("RedirectPath = %q, want /workspace/.scratch/home/user/file.txt", dec.FileRedirect.RedirectPath)
	}

	// Test allow (no redirect)
	dec = engine.CheckFile("/workspace/myproject/file.txt", "write")
	if dec.PolicyDecision != types.DecisionAllow {
		t.Errorf("PolicyDecision = %q, want allow", dec.PolicyDecision)
	}
	if dec.FileRedirect != nil {
		t.Errorf("expected nil FileRedirect for allow, got %+v", dec.FileRedirect)
	}
}

func TestCheckCommand_WithEnhancedRedirect(t *testing.T) {
	policy := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "redirect-curl",
				Commands: []string{"curl", "wget"},
				Decision: "redirect",
				Message:  "Network requests routed through audited fetch",
				RedirectTo: &CommandRedirect{
					Command:     "agentsh-fetch",
					Args:        []string{"--audit"},
					ArgsAppend:  []string{"--log-session"},
					Environment: map[string]string{"AGENTSH_AUDIT": "1"},
				},
			},
		},
	}

	engine, err := NewEngine(policy, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	dec := engine.CheckCommand("curl", []string{"https://example.com"})
	if dec.PolicyDecision != types.DecisionRedirect {
		t.Errorf("PolicyDecision = %q, want redirect", dec.PolicyDecision)
	}
	if dec.Redirect == nil {
		t.Fatal("expected Redirect, got nil")
	}
	if dec.Redirect.Command != "agentsh-fetch" {
		t.Errorf("Redirect.Command = %q, want agentsh-fetch", dec.Redirect.Command)
	}
	if len(dec.Redirect.Args) != 1 || dec.Redirect.Args[0] != "--audit" {
		t.Errorf("Redirect.Args = %v, want [--audit]", dec.Redirect.Args)
	}
	if len(dec.Redirect.ArgsAppend) != 1 || dec.Redirect.ArgsAppend[0] != "--log-session" {
		t.Errorf("Redirect.ArgsAppend = %v, want [--log-session]", dec.Redirect.ArgsAppend)
	}
	if dec.Redirect.Environment["AGENTSH_AUDIT"] != "1" {
		t.Errorf("Redirect.Environment = %v, want AGENTSH_AUDIT=1", dec.Redirect.Environment)
	}
}

func TestDecision_AuditAndSoftDelete(t *testing.T) {
	policy := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "audit-git",
				Commands: []string{"git"},
				Decision: "audit",
				Message:  "Git commands are audited",
			},
		},
		FileRules: []FileRule{
			{
				Name:       "soft-delete",
				Paths:      []string{"/workspace/**"},
				Operations: []string{"delete"},
				Decision:   "soft_delete",
				Message:    "Deletions go to trash",
			},
		},
	}

	engine, err := NewEngine(policy, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Test audit decision
	dec := engine.CheckCommand("git", []string{"push"})
	if dec.PolicyDecision != types.DecisionAudit {
		t.Errorf("PolicyDecision = %q, want audit", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q, want allow (audit is allow + logging)", dec.EffectiveDecision)
	}

	// Test soft_delete decision
	dec = engine.CheckFile("/workspace/file.txt", "delete")
	if dec.PolicyDecision != types.DecisionSoftDelete {
		t.Errorf("PolicyDecision = %q, want soft_delete", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q, want allow (soft_delete proceeds with trash)", dec.EffectiveDecision)
	}
}
