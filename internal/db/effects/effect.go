// internal/db/effects/effect.go
package effects

import "sort"

// Effect is one classified consequence of a statement, per §5.2.
type Effect struct {
	Group      Group
	Subtype    Subtype
	Objects    []ObjectRef
	Resolution Resolution
}

// canonicalGroupRank returns the within-tier ordering position per §5.2 R5.
// Lower rank = higher priority within the same tier (= sorted first).
// Groups not listed for their tier sort after listed groups, in Group enum order.
var canonicalGroupRank = map[Group]int{
	// critical: unknown > unsafe_io > schema_destroy > bulk_export > privilege
	GroupUnknown:       0,
	GroupUnsafeIO:      1,
	GroupSchemaDestroy: 2,
	GroupBulkExport:    3,
	GroupPrivilege:     4,
	// high: delete > schema_create > schema_alter > bulk_load > procedural
	GroupDelete:       0,
	GroupSchemaCreate: 1,
	GroupSchemaAlter:  2,
	GroupBulkLoad:     3,
	GroupProcedural:   4,
	// medium: modify > write > maintenance > lock
	GroupModify:      0,
	GroupWrite:       1,
	GroupMaintenance: 2,
	GroupLock:        3,
	// low: read > transaction > session > notify
	GroupRead:        0,
	GroupTransaction: 1,
	GroupSession:     2,
	GroupNotify:      3,
}

// Order sorts the slice into canonical effect order per §5.2:
//   1. Highest risk tier first.
//   2. Within tier, fixed canonical group order.
//   3. Stable for equal priority (preserves input order).
//
// Ordering is in-place. The first element after sorting is the primary effect.
func Order(effects []Effect) {
	sort.SliceStable(effects, func(i, j int) bool {
		ti, tj := effects[i].Group.RiskTier(), effects[j].Group.RiskTier()
		if ti != tj {
			return ti > tj // higher tier value sorts first
		}
		return canonicalGroupRank[effects[i].Group] < canonicalGroupRank[effects[j].Group]
	})
}
