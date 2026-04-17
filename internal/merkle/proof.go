package merkle

type Proof struct {
	Hashes [][]byte
	Left   []bool
}

func GenerateProof(t *Tree, index int) *Proof {
	if index < 0 || index >= len(t.Leaves) {
		return nil
	}

	var proof Proof
	nodes := t.Leaves
	i := index

	for len(nodes) > 1 {
		var next []*Node
		for j := 0; j < len(nodes); j += 2 {
			var left, right *Node
			left = nodes[j]
			if j+1 < len(nodes) {
				right = nodes[j+1]
			} else {
				right = nodes[j]
			}

			parent := NewParent(left, right)
			next = append(next, parent)

			if j == i || j+1 == i {
				if i%2 == 0 {
					proof.Hashes = append(proof.Hashes, right.Hash)
					proof.Left = append(proof.Left, false)
				} else {
					proof.Hashes = append(proof.Hashes, left.Hash)
					proof.Left = append(proof.Left, true)
				}
				i = len(next) - 1
			}
		}
		nodes = next
	}

	return &proof
}

func VerifyProof(leaf []byte, proof *Proof, root []byte) bool {
	hash := Hash(leaf)

	for i, h := range proof.Hashes {
		if proof.Left[i] {
			hash = HashPair(h, hash)
		} else {
			hash = HashPair(hash, h)
		}
	}

	for i := range hash {
		if hash[i] != root[i] {
			return false
		}
	}

	return true
}
