package docdb

import (
	"context"
	"errors"
	engine "stackd/engine/docdb"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

var zeroTime time.Time

const healthInterval = 30 * time.Second

func (s *Service) Start() error {
	e := s.repository.Update(context.Background(), func(tx Transaction) error {
		all, e := tx.Clusters()
		if e != nil {
			return e
		}
		for _, v := range all {
			if v.Status == "available" {
				v.Status = "starting"
				v.Endpoint = engine.Endpoint{}
				v.Operation = "reconcile"
				v.Due = s.clock.Now()
				v.Version++
				if e = tx.PutCluster(v); e != nil {
					return e
				}
				if e = s.mirrorMembers(tx, v); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	s.jobs.Start()
	return nil
}
func runtimeContext(ctx context.Context, k Key) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, InvokedBy: "rds.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "rds.amazonaws.com", SourceARN: k.ARN()}})
}
func (s *Service) specification(ctx context.Context, v Cluster) (engine.Specification, error) {
	if e := s.ensureRuntime(); e != nil {
		return engine.Specification{}, e
	}
	user, password, e := s.cipher.Open(ctx, v.Key.ARN(), v.Ciphertext)
	if e != nil {
		return engine.Specification{}, e
	}
	return engine.Specification{ID: v.RuntimeID, Username: user, Password: password, Port: v.RequestedPort}, nil
}
func jobKey(raw string) (Key, error) {
	p := strings.SplitN(raw, ":", 7)
	if len(p) != 7 || p[0] != "arn" || p[2] != "rds" {
		return Key{}, errors.New("invalid DocumentDB job key")
	}
	return Key{Scope: Scope{p[1], p[4], p[3]}, Kind: p[5], Name: p[6]}, nil
}

type clusterJobs struct{ s *Service }

func (j clusterJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := j.s.repository.View(ctx, func(r Reader) error {
		all, e := r.Clusters()
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
func (j clusterJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	k, e := jobKey(job.Key)
	if e != nil {
		return e
	}
	ctx = runtimeContext(ctx, k)
	var v Cluster
	e = s.repository.View(ctx, func(r Reader) error { var e error; v, e = r.Cluster(k); return e })
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
		return nil
	}
	var endpoint engine.Endpoint
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native DocumentDB runtime unavailable")
	} else {
		switch v.Operation {
		case "delete":
			nativeErr = s.runtime.Delete(ctx, v.RuntimeID)
		case "stop", "detach":
			nativeErr = s.runtime.Stop(ctx, v.RuntimeID)
		default:
			spec, e := s.specification(ctx, v)
			nativeErr = e
			if nativeErr == nil && v.Operation == "password" {
				_, password, e := s.cipher.Open(ctx, v.Key.ARN(), v.PendingCiphertext)
				nativeErr = e
				if nativeErr == nil {
					nativeErr = s.runtime.SetPassword(ctx, spec, password)
					spec.Password = password
				}
			}
			if nativeErr == nil && v.Operation == "reboot" {
				nativeErr = s.runtime.Stop(ctx, v.RuntimeID)
			}
			if nativeErr == nil {
				if v.RestoreSnapshot != "" {
					endpoint, nativeErr = s.runtime.Restore(ctx, spec, v.RestoreSnapshot)
				} else {
					endpoint, nativeErr = s.runtime.Ensure(ctx, spec)
				}
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Cluster(k)
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
			current.Endpoint = engine.Endpoint{}
			if current.Operation != "delete" && current.Operation != "stop" && current.Operation != "detach" {
				current.Status = "failed"
			}
			current.Version++
			current.Due = s.clock.Now().Add(healthInterval)
			if e = tx.PutCluster(current); e != nil {
				return e
			}
			return s.mirrorMembers(tx, current)
		}
		if current.Operation == "delete" {
			return tx.DeleteCluster(k)
		}
		if current.Operation == "detach" {
			members, e := membersOf(tx, current)
			if e != nil {
				return e
			}
			for _, m := range members {
				if m.Status == "deleting" {
					if e = tx.DeleteInstance(m.Key); e != nil {
						return e
					}
				}
			}
			current.Status = "creating"
			current.Endpoint = engine.Endpoint{}
			current.Due = zeroTime
		} else if current.Operation == "stop" {
			// TODO: Comeback schedule AWS's seven-day automatic restart through
			// service time; stopped native clusters currently require StartDBCluster.
			current.Status = "stopped"
			current.Endpoint = engine.Endpoint{}
			current.Due = zeroTime
		} else {
			current.Status = "available"
			current.Endpoint = endpoint
			current.Due = s.clock.Now().Add(healthInterval)
			if current.Operation == "password" {
				current.Ciphertext = current.PendingCiphertext
				current.PendingCiphertext = nil
			}
			current.RestoreSnapshot = ""
		}
		current.Operation = ""
		current.Version++
		if e = tx.PutCluster(current); e != nil {
			return e
		}
		return s.mirrorMembers(tx, current)
	})
}

type snapshotJobs struct{ s *Service }

func (j snapshotJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := j.s.repository.View(ctx, func(r Reader) error {
		all, e := r.Snapshots()
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
	var snap Snapshot
	var source Cluster
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		snap, e = r.Snapshot(k)
		if e != nil {
			return e
		}
		if snap.Operation != "delete" {
			source, e = r.Cluster(Key{Scope: k.Scope, Kind: "cluster", Name: snap.Source})
		}
		return e
	})
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if uint64(snap.Version) != job.Version || !snap.Due.Equal(job.Due) || snap.Due.After(s.clock.Now()) {
		return nil
	}
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native DocumentDB runtime unavailable")
	} else if snap.Operation == "delete" {
		nativeErr = s.runtime.DeleteSnapshot(ctx, snap.RuntimeID)
	} else if source.RuntimeID != snap.SourceRuntimeID {
		nativeErr = errors.New("snapshot source incarnation changed")
	} else {
		spec, e := s.specification(ctx, source)
		nativeErr = e
		if nativeErr == nil {
			nativeErr = s.runtime.Snapshot(ctx, spec, snap.RuntimeID)
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
		if current.Version != snap.Version || current.RuntimeID != snap.RuntimeID {
			return nil
		}
		if nativeErr != nil {
			current.Version++
			current.Due = s.clock.Now().Add(healthInterval)
			if current.Operation != "delete" {
				current.Status = "failed"
			}
			return tx.PutSnapshot(current)
		}
		if current.Operation == "delete" {
			return tx.DeleteSnapshot(k)
		}
		current.Status = "available"
		current.Operation = ""
		current.Due = zeroTime
		current.Version++
		if e = tx.PutSnapshot(current); e != nil {
			return e
		}
		v, e := tx.Cluster(source.Key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if v.RuntimeID == source.RuntimeID && v.Status == "backing-up" {
			members, e := membersOf(tx, v)
			if e != nil {
				return e
			}
			if len(members) == 0 {
				// The cold-backup owner has verified actual retained data.
				// A detached shell has no native writer to reconcile.
				v.Status = "creating"
				v.Operation = ""
				v.Due = zeroTime
				v.Version++
				return tx.PutCluster(v)
			}
			v.Status = "starting"
			v.Operation = "reconcile"
			v.Due = s.clock.Now()
			v.Version++
			if e = tx.PutCluster(v); e != nil {
				return e
			}
			return s.mirrorMembers(tx, v)
		}
		return nil
	})
}
