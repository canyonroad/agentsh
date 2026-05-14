// internal/db/effects/resolution.go
package effects

// Resolution tags an Effect's object set with a confidence level per §6.1.
type Resolution uint8

const (
	ResolutionQualified Resolution = iota
	ResolutionUnqualified
	ResolutionAmbiguousAfterSearchPath
	ResolutionMaybeTempShadowed
	ResolutionUnresolved
	ResolutionCatalogResolved
	ResolutionCatalogUnresolved
	ResolutionCatalogUnavailable
)

var resolutionNames = [...]string{
	ResolutionQualified:                "qualified_syntactic",
	ResolutionUnqualified:              "unqualified_syntactic",
	ResolutionAmbiguousAfterSearchPath: "ambiguous_after_search_path",
	ResolutionMaybeTempShadowed:        "maybe_temp_shadowed",
	ResolutionUnresolved:               "unresolved",
	ResolutionCatalogResolved:          "catalog_resolved",
	ResolutionCatalogUnresolved:        "catalog_unresolved",
	ResolutionCatalogUnavailable:       "catalog_unavailable",
}

var resolutionConfidenceRank = map[Resolution]int{
	ResolutionCatalogResolved:          0,
	ResolutionQualified:                1,
	ResolutionUnqualified:              2,
	ResolutionAmbiguousAfterSearchPath: 3,
	ResolutionMaybeTempShadowed:        4,
	ResolutionUnresolved:               5,
	ResolutionCatalogUnresolved:        6,
	ResolutionCatalogUnavailable:       7,
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
	if len(rs) == 0 {
		return ResolutionQualified
	}
	worst := rs[0]
	for _, r := range rs[1:] {
		if resolutionRank(r) > resolutionRank(worst) {
			worst = r
		}
	}
	return worst
}

func resolutionRank(r Resolution) int {
	rank, ok := resolutionConfidenceRank[r]
	if !ok {
		return resolutionConfidenceRank[ResolutionCatalogUnavailable]
	}
	return rank
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
