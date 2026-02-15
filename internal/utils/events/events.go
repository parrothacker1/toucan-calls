/// Event handling queue (more write later)

// Package events
package events

import (
	"sync"
	"sync/atomic"

	"github.com/emirpasic/gods/v2/queues/arrayqueue"
)

type EventWriter[T any] interface {
	Write(events []T)
}

type EventOptions struct {
	Capacity       uint32
	NodeSize       uint32
	WriteThreshold int
	RetryThreshold int
	Retry          bool
}

type EventQueue[T any] struct {
	nodeSize   uint32
	capacity   uint32
	bufferSize atomic.Uint32

	head   *EventNode[T]
	headMu sync.Mutex

	current   *EventNode[T]
	currentMu sync.Mutex

	poolMu    sync.Mutex
	poolNodes *arrayqueue.Queue[*EventNode[T]]

	writeThreshold int
	writer         EventWriter[T]
	writeBuffer    []T
	writeMu        sync.Mutex

	retryBuffer    []T
	shouldRetry    bool
	retryThreshold int
	isDraining     atomic.Bool
	retryMu        sync.Mutex
}

func NewEventQueue[T any](option *EventOptions, eventWriter EventWriter[T]) *EventQueue[T] {
	headNode := NewEventNode[T](option.NodeSize)
	queue := EventQueue[T]{
		capacity:       option.Capacity,
		nodeSize:       option.NodeSize,
		writeThreshold: option.WriteThreshold,
		shouldRetry:    option.Retry,
		retryThreshold: option.RetryThreshold,
		bufferSize:     atomic.Uint32{},

		head:        headNode,
		current:     headNode,
		poolNodes:   arrayqueue.New[*EventNode[T]](),
		writeBuffer: make([]T, 0, option.WriteThreshold),
		retryBuffer: make([]T, 0, option.RetryThreshold),
		writer:      eventWriter,
	}
	queue.bufferSize.Store(1)
	return &queue
}

func (q *EventQueue[T]) Push(val T) bool {
	q.currentMu.Lock()
	defer q.currentMu.Unlock()
	full, contented := q.current.Push(val)
	if !full && !contented {
		return true
	}
	if !full && contented && q.shouldRetry {
		return q.pushRetryBuffer(val)
	}
	if q.bufferSize.Load() >= q.capacity {
		return false
	}

	nextNode := q.getNextNode()
	q.current.nextNode = nextNode
	nextNode.prevNode = q.current
	q.current = nextNode
	q.bufferSize.Add(1)

	full, contented = q.current.Push(val)
	if !full && !contented {
		return true
	}
	if !full && contented && q.shouldRetry {
		return q.pushRetryBuffer(val)
	}
	return false
}

func (q *EventQueue[T]) Pop() (T, bool) {
	var zero T
	q.headMu.Lock()
	defer q.headMu.Unlock()

	if val, ok := q.head.Pop(); !ok {
		nextNode := q.head.nextNode
		if nextNode == nil {
			return zero, false
		}
		q.releaseNode(q.head)
		q.head = nextNode
		q.bufferSize.Add(^uint32(0))
	} else {
		return val, ok
	}
	val, ok := q.head.Pop()
	return val, ok
}

func (q *EventQueue[T]) Reset(write bool) {
	q.headMu.Lock()
	q.currentMu.Lock()

	defer q.currentMu.Unlock()
	defer q.headMu.Unlock()
	if write {
		buf := make([]T, 0, int(q.bufferSize.Load()*q.nodeSize))
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
	q.bufferSize.Store(1)
}

func (q *EventQueue[T]) getNextNode() *EventNode[T] {
	q.poolMu.Lock()
	defer q.poolMu.Unlock()

	if node, ok := q.poolNodes.Dequeue(); ok {
		return node
	}
	return NewEventNode[T](q.nodeSize)
}

func (q *EventQueue[T]) releaseNode(node *EventNode[T]) {
	q.poolMu.Lock()
	defer q.poolMu.Unlock()

	node.Reset()
	q.poolNodes.Enqueue(node)
}

func (q *EventQueue[T]) pushWriteBuffer(val T) bool {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if len(q.writeBuffer) >= q.writeThreshold {
		q.drainWriteBuffer()
	}
	q.writeBuffer = append(q.writeBuffer, val)
	return true
}

func (q *EventQueue[T]) drainWriteBuffer() {
	q.writer.Write(q.writeBuffer)
	q.writeBuffer = q.writeBuffer[0:]
}

func (q *EventQueue[T]) pushRetryBuffer(val T) bool {
	q.retryMu.Lock()
	defer q.retryMu.Unlock()

	if len(q.retryBuffer) >= q.retryThreshold {
		if q.isDraining.CompareAndSwap(false, true) {
			go q.drainRetryBuffer()
		}
		return false
	}
	q.retryBuffer = append(q.retryBuffer, val)
	return true
}

func (q *EventQueue[T]) drainRetryBuffer() {
	defer q.isDraining.Store(false)
	for {
		q.retryMu.Lock()
		if len(q.retryBuffer) == 0 {
			q.retryMu.Unlock()
			return
		}
		batch := make([]T, len(q.retryBuffer))
		copy(batch, q.retryBuffer)
		q.retryBuffer = q.retryBuffer[:0]
		q.retryMu.Unlock()
		for _, v := range batch {
			if ok := q.Push(v); !ok {
				q.pushWriteBuffer(v)
			}
		}
	}
}
