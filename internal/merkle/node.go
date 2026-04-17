package merkle

type Node struct {
	Hash  []byte
	Left  *Node
	Right *Node
}

func NewLeaf(data []byte) *Node {
	return &Node{
		Hash: Hash(data),
	}
}

func NewParent(left, right *Node) *Node {
	return &Node{
		Hash:  HashPair(left.Hash, right.Hash),
		Left:  left,
		Right: right,
	}
}
