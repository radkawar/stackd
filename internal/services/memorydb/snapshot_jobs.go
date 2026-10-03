package memorydb

import (
	"context"
	"errors"
	engine "stackd/engine/valkey"
	"stackd/internal/scheduler"
	"time"
)

type snapshotJobs struct{ s *Service }

func (j snapshotJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := j.s.repository.View(ctx, func(r Reader) error {
		all, e := r.AllSnapshots()
		if e != nil {
			return e
		}
		for _, v := range all {
			if v.Due.IsZero() {
				continue
			}
			candidate := scheduler.Job{Key: v.Key.ARN(), Version: uint64(v.Version), Due: v.Due}
			if !found || scheduler.Compare(candidate, next) < 0 {
				next = candidate
				found = true
			}
		}
		return nil
	})
	return next, found, e
}
func (j snapshotJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	k, e := jobKey(job.Key)
	if e != nil {
		return e
	}
	ctx = runtimeContext(ctx, k)
	var v Snapshot
	var spec engine.Specification
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		v, e = r.Snapshot(k)
		if e != nil {
			return e
		}
		if uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
			return nil
		}
		if v.Operation == "snapshot" {
			c, e := r.Cluster(Key{Scope: k.Scope, Kind: "cluster", Name: v.Source})
			if e != nil {
				return e
			}
			if c.RuntimeID != v.SourceRuntimeID {
				return errors.New("snapshot source incarnation changed")
			}
			spec, e = specification(r, c)
			return e
		}
		return nil
	})
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
		return nil
	}
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native Valkey runtime unavailable")
	} else {
		switch v.Operation {
		case "delete":
			nativeErr = s.runtime.DeleteSnapshot(ctx, v.RuntimeID)
		case "copy":
			nativeErr = s.runtime.CopySnapshot(ctx, v.CopySource, v.RuntimeID)
		default:
			nativeErr = s.runtime.Snapshot(ctx, spec, v.RuntimeID)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Snapshot(k)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Version != v.Version || current.RuntimeID != v.RuntimeID || current.Operation != v.Operation {
			return nil
		}
		if nativeErr != nil {
			if current.Operation != "delete" {
				current.Status = "failed"
			}
			current.Version++
			current.Due = s.clock.Now().Add(healthInterval)
			return tx.PutSnapshot(current)
		}
		if current.Operation == "delete" {
			if e = s.publish(tx.Context(), k, "deleted", "delete"); e != nil {
				return e
			}
			return tx.DeleteSnapshot(k)
		}
		current.Status = "available"
		current.Due = time.Time{}
		current.Version++
		if e = s.publish(tx.Context(), k, current.Status, current.Operation); e != nil {
			return e
		}
		current.Operation = ""
		current.CopySource = ""
		return tx.PutSnapshot(current)
	})
}
