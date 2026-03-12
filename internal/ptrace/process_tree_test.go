//go:build linux

package ptrace

import "testing"

func TestProcessTree_AddRoot(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(100)

	if pt.Depth(100) != 0 {
		t.Errorf("root depth = %d, want 0", pt.Depth(100))
	}
	if _, ok := pt.Parent(100); ok {
		t.Error("root should have no parent")
	}
	if pt.Size() != 1 {
		t.Errorf("size = %d, want 1", pt.Size())
	}
}

func TestProcessTree_AddChild(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(100)
	pt.AddChild(100, 200)
	pt.AddChild(200, 300)

	if pt.Depth(200) != 1 {
		t.Errorf("child depth = %d, want 1", pt.Depth(200))
	}
	if pt.Depth(300) != 2 {
		t.Errorf("grandchild depth = %d, want 2", pt.Depth(300))
	}
	parent, ok := pt.Parent(200)
	if !ok || parent != 100 {
		t.Errorf("parent of 200 = %d, ok=%v; want 100, true", parent, ok)
	}
	if pt.Size() != 3 {
		t.Errorf("size = %d, want 3", pt.Size())
	}
}

func TestProcessTree_Remove(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(100)
	pt.AddChild(100, 200)

	pt.Remove(200)
	if pt.Size() != 1 {
		t.Errorf("size after remove = %d, want 1", pt.Size())
	}
	if pt.Depth(200) != -1 {
		t.Error("removed node should return depth -1")
	}
}

func TestProcessTree_IsDescendantOf(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(1)
	pt.AddChild(1, 10)
	pt.AddChild(10, 100)

	if !pt.IsDescendantOf(100, 1) {
		t.Error("100 should be descendant of 1")
	}
	if pt.IsDescendantOf(1, 100) {
		t.Error("1 should not be descendant of 100")
	}
	if pt.IsDescendantOf(100, 999) {
		t.Error("100 should not be descendant of non-existent 999")
	}
}

func TestProcessTree_ConcurrentAccess(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(1)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			tgid := id + 100
			pt.AddChild(1, tgid)
			pt.Depth(tgid)
			pt.Parent(tgid)
			pt.Size()
			pt.Remove(tgid)
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
