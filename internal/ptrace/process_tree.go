//go:build linux

package ptrace

import "sync"

// ProcessTree tracks TGID-to-TGID parent-child relationships.
type ProcessTree struct {
	mu    sync.RWMutex
	nodes map[int]*processNode
}

type processNode struct {
	tgid     int
	parent   int
	children []int
	depth    int
}

func NewProcessTree() *ProcessTree {
	return &ProcessTree{nodes: make(map[int]*processNode)}
}

func (pt *ProcessTree) AddRoot(tgid int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.nodes[tgid] = &processNode{tgid: tgid, parent: -1, depth: 0}
}

func (pt *ProcessTree) AddChild(parentTGID, childTGID int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	parentNode := pt.nodes[parentTGID]
	depth := 0
	if parentNode != nil {
		depth = parentNode.depth + 1
		parentNode.children = append(parentNode.children, childTGID)
	}

	pt.nodes[childTGID] = &processNode{
		tgid:   childTGID,
		parent: parentTGID,
		depth:  depth,
	}
}

func (pt *ProcessTree) Remove(tgid int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	node := pt.nodes[tgid]
	if node == nil {
		return
	}

	if parent := pt.nodes[node.parent]; parent != nil {
		for i, c := range parent.children {
			if c == tgid {
				parent.children = append(parent.children[:i], parent.children[i+1:]...)
				break
			}
		}
	}

	delete(pt.nodes, tgid)
}

func (pt *ProcessTree) Depth(tgid int) int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	if node := pt.nodes[tgid]; node != nil {
		return node.depth
	}
	return -1
}

func (pt *ProcessTree) Parent(tgid int) (int, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	node := pt.nodes[tgid]
	if node == nil || node.parent == -1 {
		return 0, false
	}
	return node.parent, true
}

func (pt *ProcessTree) Children(tgid int) []int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	node := pt.nodes[tgid]
	if node == nil {
		return nil
	}
	result := make([]int, len(node.children))
	copy(result, node.children)
	return result
}

func (pt *ProcessTree) Size() int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return len(pt.nodes)
}

func (pt *ProcessTree) IsDescendantOf(tgid, ancestorTGID int) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	current := tgid
	for {
		node := pt.nodes[current]
		if node == nil || node.parent == -1 {
			return false
		}
		if node.parent == ancestorTGID {
			return true
		}
		current = node.parent
	}
}
