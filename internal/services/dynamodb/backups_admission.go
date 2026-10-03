package dynamodb

import (
	"context"
	"sync"
	"time"

	"stackd/internal/awswire"
)

type backupRequestKey struct {
	Scope
	action string
}

type backupRequestAdmission struct {
	mu   sync.Mutex
	next map[backupRequestKey]time.Time
}

// AdmitRequest applies backup control limits before generated input validation.
func (s *Service) AdmitRequest(ctx context.Context, action string) *awswire.Error {
	var interval time.Duration
	switch action {
	case "CreateBackup":
		interval = time.Second / 50
	case "ListBackups":
		interval = time.Second / 5
	case "DescribeBackup", "DeleteBackup", "RestoreTableFromBackup":
		interval = time.Second / 10
	default:
		return nil
	}
	a := &s.backupRequests
	a.mu.Lock()
	defer a.mu.Unlock()

	// Reserve at most one second of request slots. Service time replenishes
	// the allowance without fractional-token rounding or wall-clock sleeps.
	// TODO: Comeback to native cross-connection fleet admission, which can
	// exceed these documented nominal rates; its allocation scope is unmeasured.
	now := s.clock.Now()
	key := backupRequestKey{Scope: scopeFor(ctx), action: action}
	next := a.next[key]
	if next.Before(now) {
		next = now
	}
	next = next.Add(interval)
	if next.After(now.Add(time.Second)) {
		return failure("ThrottlingException", "Rate exceeded")
	}
	if a.next == nil {
		a.next = make(map[backupRequestKey]time.Time)
	}
	a.next[key] = next
	return nil
}
