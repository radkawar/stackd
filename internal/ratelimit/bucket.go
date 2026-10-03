// Package ratelimit supplies service-time token accounting. Services own quota
// values, scope, locking, retention and protocol-specific rejection behavior.
package ratelimit

import (
	"math"
	"time"
)

// Bucket is a caller-owned token budget, not durable resource state.
// Its owner must serialize access and supply positive capacity and refill rates.
type Bucket struct {
	at     time.Time
	tokens float64
}

// NewBucket starts with the service's nominal burst capacity available.
func NewBucket(at time.Time, capacity float64) Bucket {
	return Bucket{at: at, tokens: capacity}
}

// Take consumes a token, or returns the delay until one is available. Rewinding
// service time never replenishes tokens twice for the same elapsed interval.
func (b *Bucket) Take(at time.Time, capacity, refill float64) time.Duration {
	if at.After(b.at) {
		b.tokens = math.Min(capacity, b.tokens+at.Sub(b.at).Seconds()*refill)
		b.at = at
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	due := b.at.Add(time.Duration(math.Ceil((1 - b.tokens) / refill * float64(time.Second))))
	return due.Sub(at)
}
