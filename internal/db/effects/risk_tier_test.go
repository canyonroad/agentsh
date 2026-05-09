package effects

import "testing"

func TestRiskTier_StringRoundTrip(t *testing.T) {
	cases := []struct {
		tier RiskTier
		name string
	}{
		{Safe, "safe"},
		{Low, "low"},
		{Medium, "medium"},
		{High, "high"},
		{Critical, "critical"},
	}
	for _, tc := range cases {
		if got := tc.tier.String(); got != tc.name {
			t.Errorf("RiskTier(%d).String() = %q, want %q", tc.tier, got, tc.name)
		}
	}
}

func TestRiskTier_Compare(t *testing.T) {
	if Critical.Compare(High) <= 0 {
		t.Error("Critical should be greater than High")
	}
	if Low.Compare(Low) != 0 {
		t.Error("Low should equal Low")
	}
	if Safe.Compare(Critical) >= 0 {
		t.Error("Safe should be less than Critical")
	}
}
