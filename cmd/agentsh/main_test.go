package main

import "testing"

func TestVersionString(t *testing.T) {
	tests := []struct {
		name    string
		version string
		commit  string
		want    string
	}{
		{name: "empty defaults to dev", version: "", commit: "", want: "dev"},
		{name: "unknown commit ignored", version: "1.2.3", commit: "unknown", want: "1.2.3"},
		{name: "commit appended", version: "v1.2.3", commit: "abc123", want: "v1.2.3+abc123"},
		{name: "commit already in version", version: "v1.2.3-abc123", commit: "abc123", want: "v1.2.3-abc123"},
		{name: "trims whitespace", version: " 1.0 ", commit: " a1 ", want: "1.0+a1"},
	}

	origVersion, origCommit := version, commit
	t.Cleanup(func() {
		version, commit = origVersion, origCommit
	})

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			version = tt.version
			commit = tt.commit
			if got := versionString(); got != tt.want {
				t.Fatalf("versionString() = %q, want %q", got, tt.want)
			}
		})
	}
}
