package kinesis

import (
	"context"
	"sync"
	"time"

	"stackd/clock"
)

const subscriptionLifetime = 5 * time.Minute
const subscriptionRenewal = 5 * time.Second
const subscriptionBytesPerSecond = 2 << 20

// Captured frames reach 7.5 MiB of raw Data; partition keys and base64 framing
// do not reduce that budget. Throughput admission is independent of packing.
// TODO: Comeback — establish universal EFO packing and burst bounds beyond the captured workloads.
const subscriptionFrameBytes = 15 << 19

// subscriptionEnd distinguishes service-owned EOF from a disconnected client.
// Its instant remains the metric time even when a manual clock jumps past it.
type subscriptionEnd struct{ at time.Time }

func (*subscriptionEnd) Error() string { return "subscription ended" }

type subscriptionKey struct{ consumer, shard string }

type subscriptionLease struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	key      subscriptionKey
	engineID string
	expires  time.Time
}

type subscriptionSlot struct {
	lease    *subscriptionLease
	engineID string
	accepted time.Time
	// Credit is shared across renewals; a large first record may borrow credit,
	// but later pages must repay that debt at the documented delivery rate.
	credit     float64
	creditedAt time.Time
}

// The registry owns only ephemeral connection admission and delivery credit,
// never native offsets or records. One service-clock reaper removes cooldowns
// after disconnect and expires connections even while native I/O is blocked.
type subscriptions struct {
	mu      sync.Mutex
	slots   map[subscriptionKey]*subscriptionSlot
	wakeups chan struct{}
	closed  bool
	cancel  context.CancelFunc
	work    sync.WaitGroup
}

func newSubscriptions() *subscriptions {
	return &subscriptions{slots: map[subscriptionKey]*subscriptionSlot{}, wakeups: make(chan struct{}, 1)}
}

func (r *subscriptions) wake() {
	select {
	case r.wakeups <- struct{}{}:
	default:
	}
}

func (r *subscriptions) acquire(parent, lifetime context.Context, c clock.Clock, consumer, shard, engineID string) (*subscriptionLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || lifetime.Err() != nil {
		return nil, context.Canceled
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	now := c.Now()
	key := subscriptionKey{consumer: consumer, shard: shard}
	slot := r.slots[key]
	if slot != nil && now.Before(slot.accepted.Add(subscriptionRenewal)) {
		return nil, failure("ResourceInUseException", "A subscription for this consumer and shard was established less than five seconds ago.")
	}
	if r.cancel == nil {
		ctx, cancel := context.WithCancel(lifetime)
		r.cancel = cancel
		r.work.Add(1)
		go r.run(ctx, c)
	}
	if slot == nil {
		slot = &subscriptionSlot{engineID: engineID, credit: subscriptionBytesPerSecond, creditedAt: now}
		r.slots[key] = slot
	}
	if slot.lease != nil {
		slot.lease.cancel(&subscriptionEnd{at: now})
	}
	ctx, cancel := context.WithCancelCause(parent)
	lease := &subscriptionLease{ctx: ctx, cancel: cancel, key: key, engineID: engineID, expires: now.Add(subscriptionLifetime)}
	slot.lease, slot.accepted = lease, now
	r.work.Add(1)
	r.wake()
	return lease, nil
}

func refillSubscription(slot *subscriptionSlot, now time.Time) {
	if now.After(slot.creditedAt) {
		slot.credit = min(float64(subscriptionBytesPerSecond), slot.credit+now.Sub(slot.creditedAt).Seconds()*subscriptionBytesPerSecond)
		slot.creditedAt = now
	}
}

func (r *subscriptions) ready(lease *subscriptionLease, now time.Time) (bool, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	slot := r.slots[lease.key]
	if slot == nil || slot.lease != lease {
		return false, time.Time{}
	}
	refillSubscription(slot, now)
	if slot.credit >= 1 {
		return true, time.Time{}
	}
	wait := time.Duration((1-slot.credit)*float64(time.Second)/subscriptionBytesPerSecond) + time.Nanosecond
	return false, now.Add(wait)
}

func (r *subscriptions) delivered(lease *subscriptionLease, now time.Time, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A replacement can arrive while its predecessor writes the last frame.
	// Its debt still belongs to the same consumer/shard, not the old lease.
	if slot := r.slots[lease.key]; slot != nil {
		refillSubscription(slot, now)
		slot.credit = min(float64(subscriptionBytesPerSecond), slot.credit-float64(bytes))
	}
}

func (r *subscriptions) release(lease *subscriptionLease) {
	lease.cancel(context.Canceled)
	r.mu.Lock()
	if slot := r.slots[lease.key]; slot != nil && slot.lease == lease {
		slot.lease = nil
	}
	r.mu.Unlock()
	r.wake()
	r.work.Done()
}

func (r *subscriptions) cancelStream(engineID string, at time.Time) {
	r.mu.Lock()
	for key, slot := range r.slots {
		if slot.engineID != engineID {
			continue
		}
		if slot.lease != nil {
			slot.lease.cancel(&subscriptionEnd{at: at})
		}
		delete(r.slots, key)
	}
	r.mu.Unlock()
	r.wake()
}

func (r *subscriptions) run(ctx context.Context, c clock.Clock) {
	defer r.work.Done()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, slot := range r.slots {
			if slot.lease != nil {
				slot.lease.cancel(context.Canceled)
			}
		}
	}()
	for ctx.Err() == nil {
		now := c.Now()
		var deadline time.Time
		r.mu.Lock()
		for key, slot := range r.slots {
			if slot.lease != nil {
				if !now.Before(slot.lease.expires) {
					slot.lease.cancel(&subscriptionEnd{at: slot.lease.expires})
				} else {
					deadline = earlierDeadline(deadline, slot.lease.expires)
				}
				continue
			}
			refillSubscription(slot, now)
			expires := slot.accepted.Add(subscriptionRenewal)
			if slot.credit < subscriptionBytesPerSecond {
				paid := now.Add(time.Duration((subscriptionBytesPerSecond-slot.credit)*float64(time.Second)/subscriptionBytesPerSecond) + time.Nanosecond)
				if paid.After(expires) {
					expires = paid
				}
			}
			if !now.Before(expires) {
				delete(r.slots, key)
			} else {
				deadline = earlierDeadline(deadline, expires)
			}
		}
		r.mu.Unlock()
		var timer clock.Timer
		var tick <-chan time.Time
		if !deadline.IsZero() {
			timer = c.NewTimerAt(deadline)
			tick = timer.C()
		}
		select {
		case <-ctx.Done():
		case <-r.wakeups:
		case <-tick:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (r *subscriptions) close() {
	r.mu.Lock()
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	for key, slot := range r.slots {
		if slot.lease != nil {
			slot.lease.cancel(context.Canceled)
		}
		delete(r.slots, key)
	}
	r.mu.Unlock()
	r.work.Wait()
}
