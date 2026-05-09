// internal/db/effects/object.go
package effects

import "encoding/json"

// ObjectKind identifies the schema of an ObjectRef per §6.4.
type ObjectKind uint8

const (
	ObjectTable ObjectKind = iota + 1
	ObjectView
	ObjectFunction
	ObjectSchema
	ObjectIndex
	ObjectSequence
	ObjectExternalEndpoint
	ObjectFilesystemPath
	ObjectProgram
	ObjectSubscription
	ObjectPublication
	ObjectServer
	ObjectUserMapping
	ObjectTablespace
	ObjectGUC
	ObjectRole
)

var objectKindNames = map[ObjectKind]string{
	ObjectTable:            "table",
	ObjectView:             "view",
	ObjectFunction:         "function",
	ObjectSchema:           "schema",
	ObjectIndex:            "index",
	ObjectSequence:         "sequence",
	ObjectExternalEndpoint: "external_endpoint",
	ObjectFilesystemPath:   "filesystem_path",
	ObjectProgram:          "program",
	ObjectSubscription:     "subscription",
	ObjectPublication:      "publication",
	ObjectServer:           "server",
	ObjectUserMapping:      "user_mapping",
	ObjectTablespace:       "tablespace",
	ObjectGUC:              "guc",
	ObjectRole:             "role",
}

func (k ObjectKind) String() string {
	if name, ok := objectKindNames[k]; ok {
		return name
	}
	return ""
}

// ObjectRef references one named object referenced by an Effect, per §6.4.
// Fields are kind-specific; consumers should read only those for the active Kind.
// JSON encoding emits only fields populated for the active Kind.
//
// Note: for unqualified table references the spec calls for schema=null in JSON
// (§6.1). Phase 1 emits the field as absent (omitempty) — the null-vs-absent
// distinction is finalized in Plan 04 when DBEvent JSON ships.
type ObjectRef struct {
	Kind   ObjectKind
	Schema string // table/view/function/index/sequence
	Name   string // any named object
	Host   string // external_endpoint
	Port   int    // external_endpoint
	Path   string // filesystem_path
	Argv0  string // program
}

type objectRefJSON struct {
	Kind   string `json:"kind"`
	Schema string `json:"schema,omitempty"`
	Name   string `json:"name,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
	Argv0  string `json:"argv0,omitempty"`
}

// MarshalJSON emits only the fields meaningful for r.Kind.
func (r ObjectRef) MarshalJSON() ([]byte, error) {
	out := objectRefJSON{Kind: r.Kind.String()}
	switch r.Kind {
	case ObjectTable, ObjectView, ObjectFunction, ObjectIndex, ObjectSequence:
		out.Schema = r.Schema
		out.Name = r.Name
	case ObjectExternalEndpoint:
		out.Host = r.Host
		out.Port = r.Port
	case ObjectFilesystemPath:
		out.Path = r.Path
	case ObjectProgram:
		out.Argv0 = r.Argv0
	default:
		out.Name = r.Name
	}
	return json.Marshal(out)
}

// UnmarshalJSON parses the kind-discriminated form back into an ObjectRef.
func (r *ObjectRef) UnmarshalJSON(b []byte) error {
	var raw objectRefJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k, name := range objectKindNames {
		if name == raw.Kind {
			r.Kind = k
			break
		}
	}
	r.Schema = raw.Schema
	r.Name = raw.Name
	r.Host = raw.Host
	r.Port = raw.Port
	r.Path = raw.Path
	r.Argv0 = raw.Argv0
	return nil
}
