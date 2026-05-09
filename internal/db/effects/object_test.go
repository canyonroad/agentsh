// internal/db/effects/object_test.go
package effects

import (
	"encoding/json"
	"testing"
)

func TestObjectRef_TableMarshal(t *testing.T) {
	ref := ObjectRef{Kind: ObjectTable, Schema: "public", Name: "users"}
	got, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"kind":"table","schema":"public","name":"users"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestObjectRef_ExternalEndpoint(t *testing.T) {
	ref := ObjectRef{Kind: ObjectExternalEndpoint, Host: "upstream.example", Port: 5432}
	got, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"kind":"external_endpoint","host":"upstream.example","port":5432}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestObjectRef_FilesystemPath(t *testing.T) {
	ref := ObjectRef{Kind: ObjectFilesystemPath, Path: "/tmp/dump.csv"}
	got, _ := json.Marshal(ref)
	want := `{"kind":"filesystem_path","path":"/tmp/dump.csv"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestObjectRef_Program(t *testing.T) {
	ref := ObjectRef{Kind: ObjectProgram, Argv0: "/usr/bin/curl"}
	got, _ := json.Marshal(ref)
	want := `{"kind":"program","argv0":"/usr/bin/curl"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestObjectRef_NamedClusterObject(t *testing.T) {
	ref := ObjectRef{Kind: ObjectSubscription, Name: "sub_orders"}
	got, _ := json.Marshal(ref)
	want := `{"kind":"subscription","name":"sub_orders"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestObjectRef_RoundTrip(t *testing.T) {
	cases := []ObjectRef{
		{Kind: ObjectTable, Schema: "public", Name: "users"},
		{Kind: ObjectTable, Schema: "", Name: "users"}, // unqualified
		{Kind: ObjectExternalEndpoint, Host: "h", Port: 1234},
		{Kind: ObjectFilesystemPath, Path: "/p"},
		{Kind: ObjectProgram, Argv0: "/x"},
		{Kind: ObjectSubscription, Name: "s"},
	}
	for _, in := range cases {
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", in, err)
		}
		var out ObjectRef
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("Unmarshal(%s): %v", raw, err)
		}
		if out != in {
			t.Errorf("round-trip mismatch: in=%v out=%v", in, out)
		}
	}
}
