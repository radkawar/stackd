package clock_test

import (
	"testing"
	"time"

	"stackd/clock"
)

func TestRealClockAndModernTimerSemantics(t *testing.T) {
	c := clock.Real{}
	before := time.Now()
	if now := c.Now(); now.Before(before) || now.After(time.Now()) {
		t.Fatalf("real clock = %s", now)
	}
	timer := c.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() || timer.Stop() {
		t.Fatal("real timer Stop results differ")
	}
	if timer.Reset(time.Hour) {
		t.Fatal("stopped real timer reported active")
	}
	if !timer.Reset(0) {
		t.Fatal("active real timer reported inactive")
	}
	select {
	case <-timer.C():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if timer.Reset(time.Hour) {
		t.Fatal("consumed real timer reported active")
	}
	if !timer.Stop() {
		t.Fatal("rescheduled timer could not be stopped")
	}
	for _, deadline := range []time.Time{time.Now().Add(-time.Hour), time.Now()} {
		timer := c.NewTimerAt(deadline)
		select {
		case at := <-timer.C():
			if at.Before(deadline) {
				t.Fatal("absolute timer fired before its deadline")
			}
		case <-t.Context().Done():
			timer.Stop()
			t.Fatal(t.Context().Err())
		}
	}
}
