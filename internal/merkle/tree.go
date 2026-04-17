package merkle

type Tree struct {
	Root   *Node
	Leaves []*Node
}

func BuildTree(data [][]byte) *Tree {
	if len(data) == 0 {
		return &Tree{}
	}

	var leaves []*Node
	for _, d := range data {
		leaves = append(leaves, NewLeaf(d))
	}

	nodes := leaves

	for len(nodes) > 1 {
		var next []*Node
		for i := 0; i < len(nodes); i += 2 {
			if i+1 == len(nodes) {
				next = append(next, NewParent(nodes[i], nodes[i]))
			} else {
				next = append(next, NewParent(nodes[i], nodes[i+1]))
			}
		}
		nodes = next
	}

	return &Tree{
		Root:   nodes[0],
		Leaves: leaves,
	}
}

func (t *Tree) RootHash() []byte {
	if t.Root == nil {
		return nil
	}
	return t.Root.Hash
}
