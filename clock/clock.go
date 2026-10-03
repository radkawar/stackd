// Package clock supplies instance-owned clocks for service time. Manual clocks
// deliver timer notifications; they do not run or drain service goroutines,
// execute customer code, or persist scheduled jobs.
package clock

import "time"

// Clock supplies time and one-shot timers. NewTimerAt registers an absolute
// deadline in one operation, avoiding a race between reading Now and scheduling
// a relative timer when another goroutine advances a manual clock.
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
	NewTimerAt(time.Time) Timer
}

// Timer sends one value on C per firing and never closes C. Stop and Reset remove
// an unread old firing; a receive begun after they return cannot observe that
// firing. Their result is true if a scheduled or unread firing was canceled,
// false if the timer was stopped or its previous firing was already received.
// A receive concurrent with Stop or Reset may consume the old firing first.
//
// These are Go 1.23+ channel-timer semantics; callers must not drain C after Stop
// or Reset. Manual delivery is buffered and does not wait for a receiver.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// Real uses Go's wall/monotonic clock and runtime timers. Its zero value is ready
// for use. It owns no goroutines or state beyond the timers its callers create.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

func (Real) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

func (r Real) NewTimerAt(deadline time.Time) Timer {
	return r.NewTimer(time.Until(deadline))
}

type realTimer struct{ timer *time.Timer }

func (t realTimer) C() <-chan time.Time        { return t.timer.C }
func (t realTimer) Stop() bool                 { return t.timer.Stop() }
func (t realTimer) Reset(d time.Duration) bool { return t.timer.Reset(d) }

var _ Clock = Real{}
