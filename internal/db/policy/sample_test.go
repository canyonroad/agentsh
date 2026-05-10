package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Each row mirrors one example from spec §10.2. Effects are constructed
// directly; the proxy (Plan 04+) and classifier (Plan 03) will produce
// equivalent ClassifiedStatement values from real SQL.

type sampleCase struct {
	name    string
	stmt    effects.ClassifiedStatement
	service ServiceID
	want    DecisionVerb
}

func tbl(group effects.Group, sub effects.Subtype, names ...string) effects.Effect {
	objs := make([]effects.ObjectRef, len(names))
	for i, n := range names {
		objs[i] = effects.ObjectRef{Kind: effects.ObjectTable, Name: n}
	}
	return effects.Effect{Group: group, Subtype: sub, Objects: objs, Resolution: effects.ResolutionQualified}
}
func guc(sub effects.Subtype, name string) effects.Effect {
	return effects.Effect{
		Group:      effects.GroupSession,
		Subtype:    sub,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: name}},
		Resolution: effects.ResolutionQualified,
	}
}

func cases() []sampleCase {
	return []sampleCase{
		{
			name:    "SELECT * FROM users",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupRead, effects.SubtypeNone, "users")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "SELECT * FROM users JOIN orders",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupRead, effects.SubtypeNone, "users", "orders")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "INSERT INTO log SELECT * FROM x — write effect implicitly denied",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupWrite, effects.SubtypeNone, "log"), tbl(effects.GroupRead, effects.SubtypeNone, "x")}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "DELETE FROM u — deny rule fires",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupDelete, effects.SubtypeNone, "u")}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "CREATE SUBSCRIPTION — DANGEROUS rule fires",
			stmt: effects.ClassifiedStatement{Effects: []effects.Effect{
				{Group: effects.GroupUnsafeIO, Subtype: effects.SubtypeCreateSubscription,
					Objects: []effects.ObjectRef{
						{Kind: effects.ObjectSubscription, Name: "sub_orders"},
						{Kind: effects.ObjectExternalEndpoint, Host: "upstream.example", Port: 5432},
					},
					Resolution: effects.ResolutionQualified},
			}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "UPDATE users — allow",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupModify, effects.SubtypeNone, "users")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "SET TimeZone='UTC' — allowed safe session setting",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{guc(effects.SubtypeSet, "timezone")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "SET work_mem='64MB' — denied other session setting",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{guc(effects.SubtypeSet, "work_mem")}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "SET search_path = ... — denied search-path change",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{guc(effects.SubtypeSetSearchPath, "search_path")}},
			service: "appdb",
			want:    VerbDeny,
		},
	}
}

func TestSamplePolicy_WorkedExamples(t *testing.T) {
	rs := MustLoadSample()
	for _, c := range cases() {
		t.Run(c.name, func(t *testing.T) {
			d := Evaluate(c.stmt, rs, c.service)
			if d.Verb != c.want {
				t.Errorf("got Verb=%v, want %v (rule=%q reason=%q)", d.Verb, c.want, d.RuleName, d.Reason)
			}
		})
	}
}
