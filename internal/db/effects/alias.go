// internal/db/effects/alias.go
package effects

// aliasTable maps uppercase alias tokens to the groups they expand to.
// Per §5.4: CREATE does NOT expand to GroupWrite (R23 callout).
var aliasTable = map[string][]Group{
	"READ":          {GroupRead},
	"INSERT":        {GroupWrite},
	"UPDATE":        {GroupModify},
	"DELETE":        {GroupDelete},
	"REMOVE":        {GroupDelete},
	"CREATE":        {GroupSchemaCreate},
	"DROP":          {GroupSchemaDestroy},
	"ALTER":         {GroupSchemaAlter},
	"TRUNCATE":      {GroupSchemaDestroy},
	"EXPORT":        {GroupBulkExport, GroupUnsafeIO},
	"LOAD":          {GroupBulkLoad},
	"MUTATE":        {GroupWrite, GroupModify, GroupDelete},
	"SCHEMA":        {GroupSchemaCreate, GroupSchemaAlter, GroupSchemaDestroy},
	"MAINTENANCE":   {GroupMaintenance},
	"LOCK_TABLES":   {GroupLock},
	"LISTEN_NOTIFY": {GroupNotify},
	"DANGEROUS":     {GroupSchemaDestroy, GroupPrivilege, GroupUnsafeIO, GroupProcedural, GroupBulkExport, GroupLock},
}

// ExpandAlias resolves an operator-written token to a list of canonical Groups.
// Accepts uppercase aliases ("READ", "MUTATE", "DANGEROUS"), the wildcard "*"
// (all groups except GroupUnknown), or canonical lowercase group names ("read").
// Returns ok=false on unknown tokens.
func ExpandAlias(token string) ([]Group, bool) {
	if token == "*" {
		out := make([]Group, 0, len(groupTable)-1)
		for g := range groupTable {
			if g != GroupUnknown {
				out = append(out, g)
			}
		}
		return out, true
	}
	if groups, ok := aliasTable[token]; ok {
		// return a copy so callers cannot mutate the table
		return append([]Group(nil), groups...), true
	}
	if g, ok := ParseGroup(token); ok {
		return []Group{g}, true
	}
	return nil, false
}
