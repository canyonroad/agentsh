// internal/db/effects/resolution.go
package effects

// Resolution tags an Effect's object set with a confidence level per §6.1.
// Ordering is best-to-worst (lower numeric value = higher confidence),
// matching the §6.2 fold rule:
//
//   qualified_syntactic > unqualified_syntactic > ambiguous_after_search_path
//   > maybe_temp_shadowed > unresolved
type Resolution uint8

const (
	ResolutionQualified Resolution = iota
	ResolutionUnqualified
	ResolutionAmbiguousAfterSearchPath
	ResolutionMaybeTempShadowed
	ResolutionUnresolved
)

var resolutionNames = [...]string{
	ResolutionQualified:                "qualified_syntactic",
	ResolutionUnqualified:              "unqualified_syntactic",
	ResolutionAmbiguousAfterSearchPath: "ambiguous_after_search_path",
	ResolutionMaybeTempShadowed:        "maybe_temp_shadowed",
	ResolutionUnresolved:               "unresolved",
}

func (r Resolution) String() string {
	if int(r) >= len(resolutionNames) {
		return ""
	}
	return resolutionNames[r]
}

// Fold returns the worst (least-confident) Resolution in the set, per §6.2.
// Empty input returns ResolutionQualified (no objects = no doubt).
func Fold(rs []Resolution) Resolution {
	worst := ResolutionQualified
	for _, r := range rs {
		if r > worst {
			worst = r
		}
	}
	return worst
}

// ParseResolution parses the canonical lowercase resolution-tag name.
// Returns ok=false on unknown input (including the empty string).
func ParseResolution(name string) (Resolution, bool) {
	for i, n := range resolutionNames {
		if n == name {
			return Resolution(i), true
		}
	}
	return 0, false
}
