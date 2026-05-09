package effects

// RiskTier orders operation groups by severity. Critical is the highest tier.
type RiskTier uint8

const (
	Safe RiskTier = iota
	Low
	Medium
	High
	Critical
)

var riskTierNames = [...]string{
	Safe:     "safe",
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
}

func (t RiskTier) String() string {
	if int(t) >= len(riskTierNames) {
		return "unknown"
	}
	return riskTierNames[t]
}

// Compare returns >0 if t is more severe than other, <0 if less, 0 if equal.
func (t RiskTier) Compare(other RiskTier) int {
	return int(t) - int(other)
}
