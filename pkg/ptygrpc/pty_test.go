package ptygrpc

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestExecPTYStartMarshalRoundTrip(t *testing.T) {
	orig := &ExecPTYStart{
		SessionId:  "sess",
		Command:    "bash",
		Args:       []string{"-lc", "echo"},
		Argv0:      "bash",
		WorkingDir: "/work",
		Env: map[string]string{
			"KEY": "VALUE",
		},
		Rows: 24,
		Cols: 80,
	}
	b, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got ExecPTYStart
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.GetSessionId() != orig.SessionId || got.GetCommand() != orig.Command || got.GetWorkingDir() != orig.WorkingDir {
		t.Fatalf("round trip mismatch: %+v", &got)
	}
	if got.GetRows() != 24 || got.GetCols() != 80 || got.Env["KEY"] != "VALUE" {
		t.Fatalf("fields mismatch after unmarshal: %+v", &got)
	}
}

func TestExecPTYOutputMarshalRoundTrip(t *testing.T) {
	orig := &ExecPTYOutput{Data: []byte("chunk")}
	b, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got ExecPTYOutput
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(got.GetData()) != "chunk" {
		t.Fatalf("unexpected round trip: %+v", &got)
	}
}

func TestExecPTYExitMarshalRoundTrip(t *testing.T) {
	orig := &ExecPTYExit{
		ExitCode:   2,
		DurationMs: 1234,
	}
	b, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got ExecPTYExit
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.GetExitCode() != 2 || got.GetDurationMs() != 1234 {
		t.Fatalf("unexpected round trip: %+v", &got)
	}
}
