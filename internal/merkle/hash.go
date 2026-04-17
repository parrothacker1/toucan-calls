package merkle

import "crypto/sha256"

func Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func HashPair(left, right []byte) []byte {
	combined := append(left, right...)
	return Hash(combined)
}
