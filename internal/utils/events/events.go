/// Event handling queue (more write later)

// Package events
package events

import "github.com/emirpasic/gods/v2/stacks/arraystack"

type EventWriter[T any] interface {
	Write(events []T)
}

type EventOptions struct {
	Capacity       uint32
	NodeSize       uint32
	WriteThreshold uint32
}

type EventQueue[T any] struct {
	capacity       uint32
	nodeSize       uint32
	writeThreshold uint32
	bufferSize     uint32

	head        *EventNode[T]
	current     *EventNode[T]
	poolNodes   *arraystack.Stack[*EventNode[T]]
	writer      EventWriter[T]
	eventBuffer []T
}

func NewEventQueue[T any](option *EventOptions, eventWriter EventWriter[T]) *EventQueue[T] {
	headNode := NewEventNode[T](option.NodeSize)
	return &EventQueue[T]{
		capacity:       option.Capacity,
		nodeSize:       option.NodeSize,
		writeThreshold: option.WriteThreshold,
		bufferSize:     1,

		head:        headNode,
		current:     headNode,
		poolNodes:   arraystack.New[*EventNode[T]](),
		eventBuffer: make([]T, 0, option.WriteThreshold),
		writer:      eventWriter,
	}
}

func (q *EventQueue[T]) Push(val T) bool {
	if q.current.isFull() {
		nextNode := q.getNextNode()
		q.current.nextNode = nextNode
		nextNode.prevNode = q.current
		q.current = nextNode
		q.bufferSize += 1
	}
	return q.current.Push(val)
}

func (q *EventQueue[T]) Pop() (T, bool) {
	if q.current.isEmpty() {
		lastNode := q.current.prevNode
		q.releaseNode(q.current)
		q.current = lastNode
		q.bufferSize -= 1
	}
	if q.current == nil {
		var zero T
		return zero, false
	}
	val, ok := q.current.Pop()
	return val, ok
}

func (q *EventQueue[T]) Reset(write bool) {
	if write {
		buf := make([]T, 0, int(q.bufferSize*q.nodeSize))
		for n := q.head; n != nil; {
			buf = append(buf, n.PopAll()...)
			next := n.nextNode
			q.releaseNode(n)
			n = next
		}
		q.writer.Write(buf)
	} else {
		for n := q.head; n != nil; {
			next := n.nextNode
			q.releaseNode(n)
			n = next
		}
	}
	head := q.getNextNode()
	q.head = head
	q.current = head
	q.bufferSize = 1
}

func (q *EventQueue[T]) getNextNode() *EventNode[T] {
	if node, ok := q.poolNodes.Pop(); ok {
		return node
	}
	return NewEventNode[T](q.nodeSize)
}

func (q *EventQueue[T]) releaseNode(node *EventNode[T]) {
	node.Reset()
	q.poolNodes.Push(node)
}
