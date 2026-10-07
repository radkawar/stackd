package wafv2

import (
	"sync"
	"time"
)

// rateKey identifies one aggregation instance of one rate-based rule. config
// fingerprints the rate settings: AWS WAF resets a rule's counts whenever its
// window, limit, aggregation, forwarded IP or scope-down settings change.
type rateKey struct{ webACL, rule, config, key string }

type rateBucket struct {
	second int64
	count  int64
}

// rateTracker counts matching requests in one-second buckets. Like AWS WAF's
// counters, these estimates are transient process state, not durable records.
type rateTracker struct {
	mu        sync.Mutex
	instances map[rateKey][]rateBucket
	swept     time.Time
}

func newRateTracker() *rateTracker { return &rateTracker{instances: map[rateKey][]rateBucket{}} }

const maxEvaluationWindow = 600 * time.Second

func trimBuckets(buckets []rateBucket, cutoff int64) []rateBucket {
	i := 0
	for i < len(buckets) && buckets[i].second <= cutoff {
		i++
	}
	return buckets[i:]
}

// observe counts one request and reports whether the instance's rate within
// the window now exceeds the limit.
func (t *rateTracker) observe(k rateKey, now time.Time, window time.Duration, limit int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep(now)
	second := now.Unix()
	buckets := trimBuckets(t.instances[k], second-int64(window/time.Second))
	if n := len(buckets); n > 0 && buckets[n-1].second == second {
		buckets[n-1].count++
	} else {
		buckets = append(buckets, rateBucket{second, 1})
	}
	t.instances[k] = buckets
	var total int64
	for _, b := range buckets {
		total += b.count
	}
	return total > limit
}

// limited lists aggregation keys currently above the limit for one rule.
func (t *rateTracker) limited(webACL, rule, config string, now time.Time, window time.Duration, limit int64) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := now.Unix() - int64(window/time.Second)
	var out []string
	for k, buckets := range t.instances {
		if k.webACL != webACL || k.rule != rule || k.config != config {
			continue
		}
		var total int64
		for _, b := range trimBuckets(buckets, cutoff) {
			total += b.count
		}
		if total > limit {
			out = append(out, k.key)
		}
	}
	return out
}

// sweep drops instances idle beyond the largest evaluation window.
func (t *rateTracker) sweep(now time.Time) {
	if now.Sub(t.swept) < time.Minute {
		return
	}
	t.swept = now
	cutoff := now.Add(-maxEvaluationWindow).Unix()
	for k, buckets := range t.instances {
		if len(buckets) == 0 || buckets[len(buckets)-1].second <= cutoff {
			delete(t.instances, k)
		}
	}
}
