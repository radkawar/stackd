package clock

import (
	"container/heap"
	"time"
)

type manualTimer struct {
	clock    *Manual
	channel  chan time.Time
	deadline time.Time
	sequence uint64
	index    int
	overflow bool
}

func (t *manualTimer) C() <-chan time.Time { return t.channel }

func (t *manualTimer) Stop() bool {
	m := t.clock
	m.mu.Lock()
	defer m.mu.Unlock()
	return t.cancel()
}

func (t *manualTimer) Reset(d time.Duration) bool {
	m := t.clock
	m.mu.Lock()
	defer m.mu.Unlock()
	active := t.cancel()
	m.schedule(t, d)
	return active
}

// cancel runs under the clock lock, serializing removal and draining against
// Advance and other resets. A concurrent receiver may win the unread delivery.
func (t *manualTimer) cancel() bool {
	active := t.index >= 0
	if active {
		heap.Remove(&t.clock.timers, t.index)
		t.clock.shrink()
		t.clock.notify()
	}
	select {
	case <-t.channel:
		active = true
	default:
	}
	return active
}

func (t *manualTimer) deliver(at time.Time) {
	select {
	case t.channel <- at:
	default:
	}
}

type timerHeap []*manualTimer

func (h timerHeap) Len() int { return len(h) }
func (h timerHeap) Less(i, j int) bool {
	a, b := h[i], h[j]
	if a.overflow != b.overflow {
		return !a.overflow
	}
	if !a.overflow && !a.deadline.Equal(b.deadline) {
		return a.deadline.Before(b.deadline)
	}
	return a.sequence < b.sequence
}
func (h timerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *timerHeap) Push(value any) {
	t := value.(*manualTimer)
	t.index = len(*h)
	*h = append(*h, t)
}
func (h *timerHeap) Pop() any {
	index := len(*h) - 1
	t := (*h)[index]
	(*h)[index] = nil
	*h = (*h)[:index]
	t.index = -1
	return t
}

var _ Timer = (*manualTimer)(nil)
