package events

import "sync/atomic"

type slot[T any] struct {
	val T
	ver atomic.Uint32
}

type EventNode[T any] struct {
	capacity uint32
	head     atomic.Uint32
	_        [60]byte
	tail     atomic.Uint32

	buffer   []slot[T]
	nextNode *EventNode[T]
	prevNode *EventNode[T]
}

func NewEventNode[T any](size uint32) *EventNode[T] {
	if size <= 0 {
		panic("size of a node cannot be 0")
	}
	newNode := EventNode[T]{
		buffer:   make([]slot[T], size),
		capacity: size,
		head:     atomic.Uint32{},
		tail:     atomic.Uint32{},

		nextNode: nil,
		prevNode: nil,
	}
	for i := uint32(0); i < size; i++ {
		newNode.buffer[i].ver.Store(i)
	}
	return &newNode
}

func (n *EventNode[T]) Pop() (T, bool) {
	head := n.head.Load()
	slot := &n.buffer[head%n.capacity]
	seq := slot.ver.Load()
	diff := int32(seq) - int32(head+1)

	if diff == 0 {
		val := slot.val
		var zero T
		slot.val = zero
		slot.ver.Store(head + n.capacity)
		n.head.Store(head + 1)
		return val, true
	}

	var zero T
	return zero, false
}

func (n *EventNode[T]) PopAll() []T {
	head := n.head.Load()
	tail := n.tail.Load()
	if head == tail {
		return nil
	}
	out := make([]T, 0, tail-head)
	pos := head

	for pos < tail {
		s := &n.buffer[pos%n.capacity]
		seq := s.ver.Load()
		if seq != pos+1 {
			break
		}
		out = append(out, s.val)
		var zero T
		s.val = zero
		s.ver.Store(pos + n.capacity)
		pos++
	}

	if pos != head {
		n.head.Store(pos)
	}
	return out
}

func (n *EventNode[T]) Reset() {
	var zero T
	for i := range n.buffer {
		n.buffer[i].val = zero
		n.buffer[i].ver.Store(uint32(i))
	}
	n.head.Store(0)
	n.tail.Store(0)
	n.nextNode = nil
	n.prevNode = nil
}

func (n *EventNode[T]) Push(val T) (full bool, contended bool) {
	tail := n.tail.Load()
	slot := &n.buffer[tail%n.capacity]
	seq := slot.ver.Load()
	diff := int32(seq) - int32(tail)

	contended = true
	full = false

	if diff < 0 {
		full = true
		return
	}
	if diff != 0 {
		return
	}

	if !n.tail.CompareAndSwap(tail, tail+1) {
		return
	}
	slot.val = val
	slot.ver.Store(tail + 1)
	contended = false
	return
}
