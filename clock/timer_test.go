package clock

import (
	"container/heap"
	"math"
	"testing"
	"time"
)

func TestManualHeapStableDeadlineAndResetOrder(t *testing.T) {
	m := NewManual(time.Unix(0, 0))
	later := m.NewTimer(2 * time.Second).(*manualTimer)
	first := m.NewTimer(time.Second).(*manualTimer)
	reset := m.NewTimer(3 * time.Second).(*manualTimer)
	second := m.NewTimer(time.Second).(*manualTimer)
	reset.Reset(time.Second)
	// A receiver's scheduling order is intentionally not guaranteed. Verify
	// the queue that Advance consumes, including Reset's new tie-break order.
	want := []*manualTimer{first, second, reset, later}
	for _, expected := range want {
		if got := heap.Pop(&m.timers).(*manualTimer); got != expected {
			t.Fatal("timer order differs from deadline then registration sequence")
		}
	}
}

func TestManualSequenceWrapPreservesOrder(t *testing.T) {
	m := NewManual(time.Unix(0, 0))
	first := m.NewTimer(time.Second).(*manualTimer)
	m.sequence = math.MaxUint64 - 1
	second := m.NewTimer(time.Second).(*manualTimer)
	third := m.NewTimer(time.Second).(*manualTimer)
	for _, expected := range []*manualTimer{first, second, third} {
		if got := heap.Pop(&m.timers).(*manualTimer); got != expected {
			t.Fatal("sequence overflow reordered equal-deadline timers")
		}
	}
}

func TestManualHeapReleasesStoppedAndFiredTimers(t *testing.T) {
	m := NewManual(time.Unix(0, 0))
	const count = 4096
	timers := make([]Timer, count)
	for i := range timers {
		timers[i] = m.NewTimer(time.Duration(i+1) * time.Second)
	}
	for _, timer := range timers[:count-1] {
		timer.Stop()
	}
	if len(m.timers) != 1 || cap(m.timers) > 64 {
		t.Fatalf("stopped timers retain oversized heap: len=%d cap=%d", len(m.timers), cap(m.timers))
	}
	if err := m.Advance(count * time.Second); err != nil {
		t.Fatal(err)
	}
	if m.timers != nil {
		t.Fatal("clock retains a heap after final timer fires")
	}
	for _, timer := range timers {
		if timer.(*manualTimer).index != -1 {
			t.Fatal("stopped/fired timer remains indexed")
		}
	}
	for range count {
		m.NewTimer(0)
	}
	if m.timers != nil {
		t.Fatal("immediate timers retained")
	}
}
