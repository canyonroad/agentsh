package effects

// Group identifies an operation taxonomy bucket per §5 of the spec.
type Group uint8

// IDs match the spec table 1..18 so `group_id` in DBEvent is stable.
const (
	GroupRead          Group = 1
	GroupWrite         Group = 2
	GroupModify        Group = 3
	GroupDelete        Group = 4
	GroupBulkLoad      Group = 5
	GroupBulkExport    Group = 6
	GroupSchemaCreate  Group = 7
	GroupSchemaAlter   Group = 8
	GroupSchemaDestroy Group = 9
	GroupPrivilege     Group = 10
	GroupTransaction   Group = 11
	GroupSession       Group = 12
	GroupMaintenance   Group = 13
	GroupLock          Group = 14
	GroupNotify        Group = 15
	GroupProcedural    Group = 16
	GroupUnsafeIO      Group = 17
	GroupUnknown       Group = 18
)

type groupInfo struct {
	name string
	tier RiskTier
}

var groupTable = map[Group]groupInfo{
	GroupRead:          {"read", Low},
	GroupWrite:         {"write", Medium},
	GroupModify:        {"modify", Medium},
	GroupDelete:        {"delete", High},
	GroupBulkLoad:      {"bulk_load", High},
	GroupBulkExport:    {"bulk_export", Critical},
	GroupSchemaCreate:  {"schema_create", High},
	GroupSchemaAlter:   {"schema_alter", High},
	GroupSchemaDestroy: {"schema_destroy", Critical},
	GroupPrivilege:     {"privilege", Critical},
	GroupTransaction:   {"transaction", Low},
	GroupSession:       {"session", Low},
	GroupMaintenance:   {"maintenance", Medium},
	GroupLock:          {"lock", Medium},
	GroupNotify:        {"notify", Low},
	GroupProcedural:    {"procedural", High},
	GroupUnsafeIO:      {"unsafe_io", Critical},
	GroupUnknown:       {"unknown", Critical},
}

func (g Group) String() string {
	if info, ok := groupTable[g]; ok {
		return info.name
	}
	return "unknown"
}

func (g Group) RiskTier() RiskTier {
	if info, ok := groupTable[g]; ok {
		return info.tier
	}
	return Critical // unknown is critical per §5; default unknown values to critical
}

// ID returns the canonical numeric ID per §5 (used by DBEvent.operation_group_id).
func (g Group) ID() uint8 { return uint8(g) }

// ParseGroup parses the canonical lowercase group name. Returns ok=false on unknown input.
func ParseGroup(name string) (Group, bool) {
	for g, info := range groupTable {
		if info.name == name {
			return g, true
		}
	}
	return 0, false
}
