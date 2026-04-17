/// Event Ingestion Module
/// The main purpose of this module is for ingestion of events of any
/// type and store them in a queue and pop them in the order they were
/// pushed as needed.
/// The architecture is based on the concept of dividing the queue and
/// using them. So every event is stored in a EventNode (read more about
/// EventNode in events/node.go) and these EventNodes are attached using
/// a doubly linked list for maintaining the order of the nodes. The N
/// number of producer workers can push into the tail node simultaneoussly
/// with minimal locks. We are focusing on single consumer setup for now (
/// can't see the need for multiple consumers) and again here also using
/// minimal locks and atomics for handling the pops.
/// More detailed explanation is, so each Node follows Vyukov model (again
/// read more about this in the node.go file) and each of them are chained
/// using a DLL and we pop from the head node and push into the tail node.
/// Each node pushes are lock free (inside the node) and the locks inside
/// the queue is there to handle change of nodes and updation of other values
/// and all

// Package events
package events

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

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
	Write          bool
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
	shouldWrite    bool
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
	queue := &EventQueue[T]{
		capacity:       option.Capacity,
		nodeSize:       option.NodeSize,
		writeThreshold: option.WriteThreshold,
		shouldRetry:    option.Retry,
		shouldWrite:    option.Write,
		retryThreshold: option.RetryThreshold,
		bufferSize:     atomic.Uint32{},

		head:      headNode,
		current:   headNode,
		poolNodes: arrayqueue.New[*EventNode[T]](),
	}
	if queue.shouldWrite {
		queue.writeBuffer = make([]T, 0, option.WriteThreshold)
		queue.writer = eventWriter
	}
	if queue.shouldRetry {
		queue.retryBuffer = make([]T, 0, option.RetryThreshold)
	}
	queue.bufferSize.Store(1)
	return queue
}

func (q *EventQueue[T]) Push(val T) bool {
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
	q.currentMu.Lock()
	defer q.currentMu.Unlock()

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
		if q.shouldWrite {
			q.pushWriteBuffer(val)
		}
		return val, ok
	}
	val, ok := q.head.Pop()
	if q.shouldWrite {
		q.pushWriteBuffer(val)
	}
	return val, ok
}

func (q *EventQueue[T]) Reset(write bool) {
	q.headMu.Lock()
	q.currentMu.Lock()
	q.writeMu.Lock()

	defer q.writeMu.Unlock()
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
		// Flush any events sitting in the writeBuffer
		buf = append(buf, q.writeBuffer...)
		q.writeBuffer = q.writeBuffer[:0]
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

// Run starts a consumer goroutine that continuously drains the queue
// and feeds events to the writer. It blocks until ctx is cancelled.
func (q *EventQueue[T]) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final drain before exiting
			for {
				if _, ok := q.Pop(); !ok {
					break
				}
			}
			// Flush any remaining events in the write buffer
			q.writeMu.Lock()
			if q.shouldWrite && len(q.writeBuffer) > 0 {
				q.drainWriteBuffer()
			}
			q.writeMu.Unlock()
			return
		case <-ticker.C:
			for {
				if _, ok := q.Pop(); !ok {
					break
				}
			}
		}
	}
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
	if !q.shouldWrite {
		return false
	}
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
	q.writeBuffer = q.writeBuffer[:0]
}

func (q *EventQueue[T]) pushRetryBuffer(val T) bool {
	if !q.shouldRetry {
		return false
	}
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
			if ok := q.Push(v); !ok && q.shouldWrite {
				q.pushWriteBuffer(v)
			}
		}
	}
}
