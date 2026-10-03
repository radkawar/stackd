package scheduler

import (
	"runtime"
	"time"

	"stackd/clock"
)

func (d *execution) run() {
	defer close(d.done)
	// Recovery scans also discover commits made through another repository
	// client, which cannot necessarily deliver this instance's wake hint.
	var timer clock.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		// Anchor before storage work. A clock advance during that work must
		// not move this recovery deadline forward a second time.
		next := d.clock.Now().Add(time.Second)
		result, err := d.RunDue(d.ctx, 256)
		if d.ctx.Err() != nil {
			return
		}
		if err == nil && result.More {
			// Continue a backlog without requiring another manual advance,
			// while giving other goroutines a turn between bounded batches.
			next = d.clock.Now()
			runtime.Gosched()
		} else if err == nil && result.Next != nil && result.Next.Before(next) {
			next = *result.Next
		}
		timer = d.clock.NewTimerAt(next)
		select {
		case <-d.ctx.Done():
			return
		case <-d.wake:
		case <-timer.C():
		}
		timer.Stop()
		timer = nil
	}
}
