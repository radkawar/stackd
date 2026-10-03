package ebs

import (
	"context"
	"sync"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/ratelimit"
)

// API budgets are process-local, like Step Functions admission. Resource counts
// belong to the repository instead. Nominal bursts use one second of the
// documented rate; this does not model AWS's unmeasured distributed allocator.
type snapshotAdmission struct {
	mu      sync.Mutex
	budgets map[snapshotAdmissionKey]ratelimit.Bucket
}

type snapshotAdmissionKey struct {
	Scope
	action, snapshot string
}

func (a *snapshotAdmission) allow(key snapshotAdmissionKey, at time.Time, capacity, rate float64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	budget, exists := a.budgets[key]
	if !exists {
		budget = ratelimit.NewBucket(at, capacity)
	}
	allowed := budget.Take(at, capacity, rate) == 0
	if a.budgets == nil {
		a.budgets = make(map[snapshotAdmissionKey]ratelimit.Bucket)
	}
	a.budgets[key] = budget
	return allowed
}

// forget retires per-snapshot budgets when the owning snapshot layer is deleted.
// Account budgets remain shared across callers and snapshot incarnations.
func (a *snapshotAdmission) forget(key SnapshotKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.budgets, snapshotAdmissionKey{Scope: key.Scope, action: "GetSnapshotBlock", snapshot: key.ID})
	delete(a.budgets, snapshotAdmissionKey{Scope: key.Scope, action: "PutSnapshotBlock", snapshot: key.ID})
}

func (s *Service) admitAccount(ctx context.Context, action string) *awswire.Error {
	scope := scopeFor(ctx)
	var rate float64
	switch action {
	case "StartSnapshot", "CompleteSnapshot":
		rate = 10
	case "ListSnapshotBlocks", "ListChangedBlocks":
		rate = 50
	case "GetSnapshotBlock", "PutSnapshotBlock":
		rate = 1000
		switch scope.Region {
		case "us-east-1", "us-east-2", "us-west-2", "ap-southeast-1", "eu-west-1":
			rate = 5000
		}
	default:
		return nil
	}
	if s.admission.allow(snapshotAdmissionKey{Scope: scope, action: action}, s.clock.Now(), rate, rate) {
		return nil
	}
	return failure("RequestThrottledException", "The account request rate has been exceeded.", "ACCOUNT_THROTTLED", 400)
}

func (s *Service) admitBlock(key SnapshotKey, action string) *awswire.Error {
	if s.admission.allow(snapshotAdmissionKey{Scope: key.Scope, action: action, snapshot: key.ID}, s.clock.Now(), 1000, 1000) {
		return nil
	}
	return failure("RequestThrottledException", "The snapshot request rate has been exceeded.", "RESOURCE_LEVEL_THROTTLE", 400)
}
