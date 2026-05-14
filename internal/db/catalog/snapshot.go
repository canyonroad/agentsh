package catalog

type Snapshot struct {
	relationsByOID  map[OID]Relation
	relationsByName map[Name]Relation
	relationsByBare map[string][]Relation
	functionsByOID  map[OID]Function
	functionsByName map[Name][]Function
}

func NewSnapshot(relations []Relation, functions []Function) Snapshot {
	s := Snapshot{
		relationsByOID:  make(map[OID]Relation, len(relations)),
		relationsByName: make(map[Name]Relation, len(relations)),
		relationsByBare: make(map[string][]Relation, len(relations)),
		functionsByOID:  make(map[OID]Function, len(functions)),
		functionsByName: make(map[Name][]Function, len(functions)),
	}
	for _, rel := range relations {
		s.relationsByOID[rel.OID] = rel
		s.relationsByName[rel.Name] = rel
		s.relationsByBare[rel.Name.Name] = append(s.relationsByBare[rel.Name.Name], rel)
	}
	for _, fn := range functions {
		s.functionsByOID[fn.OID] = fn
		s.functionsByName[fn.Name] = append(s.functionsByName[fn.Name], fn)
	}
	return s
}

func (s Snapshot) RelationByOID(oid OID) (Relation, bool) {
	rel, ok := s.relationsByOID[oid]
	return rel, ok
}

func (s Snapshot) RelationByName(name Name) (Relation, bool) {
	rel, ok := s.relationsByName[name]
	return rel, ok
}

func (s Snapshot) RelationsByUnqualifiedName(name string) []Relation {
	in := s.relationsByBare[name]
	out := make([]Relation, len(in))
	copy(out, in)
	return out
}

func (s Snapshot) FunctionByOID(oid OID) (Function, bool) {
	fn, ok := s.functionsByOID[oid]
	return fn, ok
}

func (s Snapshot) FunctionsByName(name Name) []Function {
	in := s.functionsByName[name]
	out := make([]Function, len(in))
	copy(out, in)
	return out
}
