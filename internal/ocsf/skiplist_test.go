package ocsf

import "testing"

// TestSkiplistReasonsNonEmpty asserts every skiplist entry has a
// non-empty reason. A blank reason is a hygiene failure — operators
// reading the file deserve to know why a Type was excluded.
func TestSkiplistReasonsNonEmpty(t *testing.T) {
	for k, v := range skiplist {
		if v == "" {
			t.Errorf("skiplist[%q] has empty reason", k)
		}
	}
}

// TestSkiplistDoesNotShadowRegistry asserts no skiplist entry is also
// a registered or pending production Type. A collision means a real
// event is being silently dropped from OCSF mapping.
func TestSkiplistDoesNotShadowRegistry(t *testing.T) {
	for k := range skiplist {
		if _, ok := registry[k]; ok {
			t.Errorf("skiplist[%q] is also registered — production Type cannot be skiplisted", k)
		}
		if _, ok := pendingTypes[k]; ok {
			t.Errorf("skiplist[%q] is also in pendingTypes — production Type cannot be skiplisted", k)
		}
	}
}
