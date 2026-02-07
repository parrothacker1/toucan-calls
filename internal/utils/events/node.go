package events

import "sync"

type EventNode[T any] struct {
	nodeMu sync.Mutex

	capacity uint32
	head     uint32
	tail     uint32

	buffer   []T
	nextNode *EventNode[T]
	prevNode *EventNode[T]
}

func NewEventNode[T any](size uint32) *EventNode[T] {
	return &EventNode[T]{
		buffer:   make([]T, size),
		capacity: size,
		head:     0,
		tail:     0,

		nextNode: nil,
		prevNode: nil,
	}

}

func (n *EventNode[T]) Pop() (T, bool) {
	var result, zero T
	n.nodeMu.Lock()
	defer n.nodeMu.Unlock()

	if n.isEmpty() {
		return zero, false
	}
	result = n.buffer[n.head]
	n.buffer[n.head] = zero
	n.head = (n.head + 1) % n.capacity
	return result, true
}

func (n *EventNode[T]) PopAll() []T {
	var zero T
	n.nodeMu.Lock()
	defer n.nodeMu.Unlock()

	if n.isEmpty() {
		return nil
	}

	result := make([]T, 0, n.capacity)
	if n.head < n.tail {
		result = append(result, n.buffer[n.head:n.tail]...)
	} else {
		result = append(result, n.buffer[n.head:]...)
		result = append(result, n.buffer[:n.tail]...)
	}

	for i := range n.buffer {
		n.buffer[i] = zero
	}
	n.head = 0
	n.tail = 0
	n.nextNode = nil

	return result
}

func (n *EventNode[T]) Push(val T) bool {
	n.nodeMu.Lock()
	defer n.nodeMu.Unlock()
	if n.isFull() {
		return false
	}
	n.buffer[n.tail] = val
	n.tail = (n.tail + 1) % n.capacity
	return true
}

func (n *EventNode[T]) Reset() {
	var zero T
	n.nodeMu.Lock()
	defer n.nodeMu.Unlock()
	for i := range n.buffer {
		n.buffer[i] = zero
	}
	n.head = 0
	n.tail = 0
	n.nextNode = nil
}

func (n *EventNode[T]) isFull() bool {
	return ((n.tail + 1) % n.capacity) == n.head
}

func (n *EventNode[T]) isEmpty() bool {
	return n.head == n.tail
}
