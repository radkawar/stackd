package rds

import (
	"context"
	"errors"
	"time"

	engine "stackd/engine/rds"
	"stackd/internal/scheduler"
)

type snapshotJobs struct {
	s *Service
}

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
				next, found = candidate, true
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
	var source Database
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		v, e = r.Snapshot(k)
		if e != nil {
			return e
		}
		if v.Status != "creating" {
			return nil
		}
		kind := "db"
		if k.Kind == "cluster-snapshot" {
			kind = "cluster"
		}
		source, e = r.Database(Key{Scope: k.Scope, Kind: kind, Name: v.Source})
		return e
	})
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if v.Due.IsZero() || uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
		return nil
	}
	var nativeErr, readyErr error
	var endpoint engine.Endpoint
	if s.runtime == nil {
		nativeErr = errors.New("native RDS runtime unavailable")
	} else if v.Status == "deleting" {
		nativeErr = s.runtime.DeleteSnapshot(ctx, v.RuntimeID)
	} else if v.Status == "creating" {
		if source.RuntimeID != v.SourceRuntimeID || source.Status != "backing-up" || source.Operation != "snapshot" {
			nativeErr = errors.New("snapshot source incarnation is unavailable")
		} else {

			user, password, err := s.cipher.Open(ctx, k.ARN(), v.Ciphertext)
			nativeErr = err
			if nativeErr == nil {

				spec := engine.Specification{ID: v.SourceRuntimeID, Engine: v.Engine, Database: v.DatabaseName, Username: user, Password: password, Parameters: v.Parameters}
				nativeErr = s.runtime.Snapshot(ctx, spec, v.RuntimeID)
				endpoint, readyErr = s.runtime.Ensure(ctx, spec)

			} else {
				readyErr = nativeErr
			}

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
		if current.Version != v.Version || current.RuntimeID != v.RuntimeID {
			return nil
		}
		if current.Status == "deleting" {

			if nativeErr == nil {
				return tx.DeleteSnapshot(k)
			}
			current.Due = s.clock.Now().Add(healthInterval)
			current.Version++
			return tx.PutSnapshot(current)

		}
		current.Due = time.Time{}
		current.Version++
		current.Status = "available"
		if nativeErr != nil {
			current.Status = "failed"
		}
		if e = tx.PutSnapshot(current); e != nil {
			return e
		}
		if nativeErr == nil && s.events != nil {
			if e = s.events.PublishRDSEvent(tx.Context(), RDSEvent{ARN: k.ARN(), Identifier: k.Name, Kind: k.Kind, Status: "available", Operation: "snapshot", Message: "Snapshot created", At: s.clock.Now()}); e != nil {
				return e
			}
		}
		src, e := tx.Database(source.Key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if src.RuntimeID != v.SourceRuntimeID || src.Operation != "snapshot" {
			return nil
		}
		src.Version++
		src.Endpoint = endpoint
		src.Status = "available"
		src.Operation = ""
		src.Due = s.clock.Now().Add(healthInterval)
		if readyErr != nil || endpoint.Address == "" {

			src.Status = "starting"
			src.Endpoint = engine.Endpoint{}
			src.Operation = "reconcile"
			src.Due = s.clock.Now()

		}
		if e = tx.PutDatabase(src); e != nil {
			return e
		}
		if src.Key.Kind == "cluster" {
			return s.mirrorMembers(tx, src)
		}
		return nil
	})
}
