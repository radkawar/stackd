package sqs

import (
	"cmp"
	"slices"
	"time"
)

type tenantLoad struct {
	queued, inflight int
	until            time.Time
}

// updateFairness derives concurrency from live deliveries. Only the noisy
// classification and its last in-flight deadline need retained state: counters
// must follow deletion, visibility changes, retention and redrive automatically.
func (q *queue) updateFairness(now time.Time) (int, map[string]tenantLoad) {
	groups := make(map[string]tenantLoad)
	total := 0
	for _, m := range q.messages {
		expires := m.retentionStarted.Add(time.Duration(q.config.retention) * time.Second)
		if !now.Before(expires) {
			continue
		}
		inflight := m.receives > 0 && now.Before(m.available)
		if inflight {
			total++
		}
		if q.config.fifo || m.group == "" {
			// Every ungrouped message is a distinct tenant, never an aggregate
			// tenant that can cross the concurrency threshold.
			continue
		}
		load := groups[m.group]
		load.queued++
		if inflight {
			load.inflight++
			until := m.available
			if expires.Before(until) {
				until = expires
			}
			if until.After(load.until) {
				load.until = until
			}
		}
		groups[m.group] = load
	}
	for group, until := range q.noisyGroups {
		load := groups[group]
		if load.queued == 0 {
			delete(q.noisyGroups, group)
			continue
		}
		if load.inflight > 0 {
			until = load.until
		} else if until.After(now) {
			// Explicit deletion/visibility changes ended processing earlier
			// than its prior deadline. Natural expiry retains the deadline,
			// even when a manual clock jumps across the entire quiet period.
			until = now
		}
		if !now.Before(until.Add(5 * time.Minute)) {
			delete(q.noisyGroups, group)
		} else {
			q.noisyGroups[group] = until
		}
	}
	// AWS documents at least 30 concurrent messages and more than 10% of the
	// queue's concurrency. Distributed detection is approximate; our decision
	// uses the transaction's service-time snapshot.
	// TODO: Comeback capture and implement recent processing-time share detection and complete native fairness recovery/threshold conformance.
	for group, load := range groups {
		if load.inflight >= 30 && load.inflight*10 > total {
			if q.noisyGroups == nil {
				q.noisyGroups = make(map[string]time.Time)
			}
			q.noisyGroups[group] = load.until
		}
	}
	return total, groups
}

func (q *queue) prioritizeMessages(candidates []*message, groups map[string]tenantLoad) {
	if len(q.noisyGroups) == 0 {
		return
	}
	// Preserve queue order among quiet tenants. Noisy tenants use spare
	// capacity, with the least concurrency first; this is not FIFO locking.
	// Each batch uses one concurrency snapshot; the next receive sees its claims.
	slices.SortStableFunc(candidates, func(a, b *message) int {
		_, aNoisy := q.noisyGroups[a.group]
		_, bNoisy := q.noisyGroups[b.group]
		if aNoisy != bNoisy {
			if aNoisy {
				return 1
			}
			return -1
		}
		if aNoisy {
			return cmp.Compare(groups[a.group].inflight, groups[b.group].inflight)
		}
		return 0
	})
}
