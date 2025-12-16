package cli

import "testing"

func TestSessionAttach_Wired(t *testing.T) {
	root := newSessionCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "attach" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session attach command to be registered")
	}
}

func TestSplitArgs_BasicQuotes(t *testing.T) {
	got, err := splitArgs(`echo "hello world"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "echo" || got[1] != "hello world" {
		t.Fatalf("unexpected split result: %v", got)
	}
}
