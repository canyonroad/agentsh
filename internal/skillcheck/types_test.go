package skillcheck

import "testing"

func TestSeverityWeight(t *testing.T) {
	cases := []struct {
		s    Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityInfo, 0},
		{Severity("garbage"), 5}, // unknown fails closed
	}
	for _, c := range cases {
		if got := c.s.Weight(); got != c.want {
			t.Errorf("Severity(%q).Weight()=%d want %d", c.s, got, c.want)
		}
	}
}

func TestVerdictActionWeightOrdering(t *testing.T) {
	if VerdictBlock.weight() <= VerdictApprove.weight() {
		t.Errorf("block should outweigh approve")
	}
	if VerdictApprove.weight() <= VerdictWarn.weight() {
		t.Errorf("approve should outweigh warn")
	}
	if VerdictWarn.weight() <= VerdictAllow.weight() {
		t.Errorf("warn should outweigh allow")
	}
}

func TestVerdictHighestAction(t *testing.T) {
	v := Verdict{
		Action: VerdictAllow,
		Skills: map[string]SkillVerdict{
			"a": {Skill: SkillRef{Name: "a"}, Action: VerdictWarn},
			"b": {Skill: SkillRef{Name: "b"}, Action: VerdictBlock},
		},
	}
	if v.HighestAction() != VerdictBlock {
		t.Errorf("HighestAction()=%s want block", v.HighestAction())
	}
}

func TestSkillRefString(t *testing.T) {
	r := SkillRef{Name: "foo", SHA256: "abc123"}
	if got := r.String(); got != "foo@abc123" {
		t.Errorf("got %q", got)
	}
}
