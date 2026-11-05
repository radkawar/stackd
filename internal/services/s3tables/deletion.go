package s3tables

import (
	"context"
	"sync"
	"time"

	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/scheduler"
)

// DeleteTable commits immediate catalog/data revocation and durable reclamation
// intent. The shared scheduler removes real bytes outside the metadata transaction.
func (s *Service) deleteTable(ctx context.Context, tx Transaction, in *api.DeleteTableInput) (*api.DeleteTableOutput, error) {
	v, e := s.table(ctx, tx, "DeleteTable", value(in.TableBucketARN), value(in.Namespace), value(in.Name))
	if e != nil {
		return nil, e
	}
	if in.VersionToken != nil && value(in.VersionToken) != v.VersionToken {
		return nil, conflict("The table version token is stale")
	}
	v.Deleted = true
	v.CleanupAt = s.clock.Now().UTC()
	if e = tx.PutTable(v); e != nil {
		return nil, e
	}
	s.notify()
	return &api.DeleteTableOutput{}, nil
}
func (s *Service) warehouseLock(warehouse string) *sync.Mutex {
	if v, ok := s.flights.Load(warehouse); ok {
		return v.(*sync.Mutex)
	}
	v, _ := s.flights.LoadOrStore(warehouse, &sync.Mutex{})
	return v.(*sync.Mutex)
}
func (s *Service) JobSource() scheduler.Source { return s }
func (s *Service) SetWake(f func())            { s.wakeMu.Lock(); s.wake = f; s.wakeMu.Unlock() }
func (s *Service) notify() {
	s.wakeMu.Lock()
	f := s.wake
	s.wakeMu.Unlock()
	if f != nil {
		f()
	}
}

// A table ARN identifies one immutable incarnation and has exactly one deletion
// generation. API version tokens fence the selected row again on completion.
func (s *Service) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var out scheduler.Job
	found := false
	e := s.repository.View(ctx, func(r Reader) error {
		rows, e := r.PendingTables()
		if e != nil {
			return e
		}
		for _, v := range rows {
			if !found || v.CleanupAt.Before(out.Due) || (v.CleanupAt.Equal(out.Due) && v.ARN < out.Key) {
				out = scheduler.Job{Key: v.ARN, Version: 1, Due: v.CleanupAt}
				found = true
			}
		}
		return nil
	})
	return out, found, e
}
func (s *Service) Run(ctx context.Context, job scheduler.Job) error {
	var before Table
	found := false
	if e := s.repository.View(ctx, func(r Reader) error {
		rows, e := r.PendingTables()
		if e != nil {
			return e
		}
		for _, v := range rows {
			if v.ARN == job.Key && job.Version == 1 && !v.CleanupAt.After(s.clock.Now()) {
				before = v
				found = true
				break
			}
		}
		return nil
	}); e != nil {
		return e
	}
	if !found {
		return nil
	}
	lock := s.warehouseLock(before.Warehouse)
	lock.Lock()
	defer lock.Unlock()
	var effect error
	if s.objects == nil {
		effect = failure("InternalServerErrorException", "Table warehouse storage is unavailable", 503)
	} else {
		effect = s.objects.PurgeWarehouse(ctx, before.Warehouse)
	}
	e := s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Warehouse(before.Scope, before.Warehouse)
		if e != nil {
			return e
		}
		if !current.Deleted || current.Purged || current.VersionToken != before.VersionToken {
			return nil
		}
		if effect == nil {
			current.Purged = true
			current.MetadataLocation = ""
			current.CleanupAt = time.Time{}
		} else {
			current.CleanupAt = s.clock.Now().Add(time.Second).UTC()
		}
		return tx.PutTable(current)
	})
	if e != nil {
		return e
	}
	return effect
}
