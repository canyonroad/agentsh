package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func BenchmarkEvaluate_AllowReadUsers(b *testing.B) {
	rs := MustLoadSample()
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}}, Resolution: effects.ResolutionQualified},
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(stmt, rs, "appdb")
	}
}

func BenchmarkEvaluate_DenyDangerous(b *testing.B) {
	rs := MustLoadSample()
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupSchemaDestroy, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "u"}}, Resolution: effects.ResolutionQualified},
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(stmt, rs, "appdb")
	}
}

func BenchmarkEvaluateConnection_Allow(b *testing.B) {
	rs := MustLoadSample()
	info := ConnectionInfo{Service: "warehouse", MatchKind: MatchConnect}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EvaluateConnection(info, rs)
	}
}
