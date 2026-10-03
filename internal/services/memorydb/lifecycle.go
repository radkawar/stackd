package memorydb

import (
	"context"
	"errors"
	engine "stackd/engine/valkey"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

const healthInterval = 30 * time.Second

// Start discards retained readiness until the native cluster has reattached.
func (s *Service) Start() error {
	e := s.repository.Update(context.Background(), func(tx Transaction) error {
		all, e := tx.AllClusters()
		if e != nil {
			return e
		}
		for _, v := range all {
			if v.Status == "available" {
				v.Status = "starting"
				v.Deployment = engine.Deployment{}
				v.Operation = "reconcile"
				v.Version++
				v.Due = s.clock.Now()
				if e = tx.PutCluster(v); e != nil {
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
func jobKey(raw string) (Key, error) {
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "memorydb" {
		return Key{}, errors.New("invalid retained MemoryDB job ARN")
	}
	resource := strings.SplitN(parts[5], "/", 2)
	if len(resource) != 2 {
		return Key{}, errors.New("invalid retained MemoryDB resource")
	}
	return Key{Scope: Scope{parts[1], parts[4], parts[3]}, Kind: resource[0], Name: resource[1]}, nil
}
func runtimeContext(ctx context.Context, k Key) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, InvokedBy: "memorydb.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "memorydb.amazonaws.com", SourceARN: k.ARN()}})
}
func specification(r Reader, v Cluster) (engine.Specification, error) {
	spec := engine.Specification{ID: v.RuntimeID, Shards: v.Shards, Replicas: v.Replicas, ClusterMode: true, TLSEnabled: v.TLSEnabled, MemoryBytes: 1 << 30}
	a := defaultACL(v.Key.Scope)
	if v.ACLName != "open-access" {
		var e error
		a, e = r.ACL(Key{Scope: v.Key.Scope, Kind: "acl", Name: v.ACLName})
		if e != nil {
			return spec, e
		}
	}
	for _, name := range a.Users {
		u := defaultUser(v.Key.Scope)
		if name != "default" {
			var e error
			u, e = r.User(Key{Scope: v.Key.Scope, Kind: "user", Name: name})
			if e != nil {
				return spec, e
			}
		}
		spec.Users = append(spec.Users, nativeUser(u))
	}
	p, ok := defaultParameterGroup(v.Key.Scope, v.ParameterGroup)
	if !ok {
		var e error
		p, e = r.ParameterGroup(Key{Scope: v.Key.Scope, Kind: "parametergroup", Name: v.ParameterGroup})
		if e != nil {
			return spec, e
		}
	}
	spec.Parameters = p.Parameters
	return spec, nil
}

type clusterJobs struct{ s *Service }

func (j clusterJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := j.s.repository.View(ctx, func(r Reader) error {
		all, e := r.AllClusters()
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
	var spec engine.Specification
	blocked := false
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		v, e = r.Cluster(k)
		if e != nil {
			return e
		}
		if uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
			return nil
		}
		if v.Operation == "delete" {
			snapshots, e := r.Snapshots(k.Scope)
			if e != nil {
				return e
			}
			for _, snap := range snapshots {
				if snap.SourceRuntimeID == v.RuntimeID && snap.Operation == "snapshot" {
					blocked = true
				}
			}
			return nil
		}
		spec, e = specification(r, v)
		return e
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
	if blocked {
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, e := tx.Cluster(k)
			if e != nil {
				return e
			}
			if current.Version != v.Version || current.RuntimeID != v.RuntimeID {
				return nil
			}
			current.Due = s.clock.Now().Add(time.Second)
			current.Version++
			return tx.PutCluster(current)
		})
	}
	var deployment engine.Deployment
	var sample *engine.Statistics
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native Valkey runtime unavailable")
	} else if v.Operation == "delete" {
		nativeErr = s.runtime.Delete(ctx, v.RuntimeID)
	} else {
		if v.RestoreSnapshot != "" {
			deployment, nativeErr = s.runtime.Restore(ctx, spec, v.RestoreSnapshot)
		} else {
			deployment, nativeErr = s.runtime.Ensure(ctx, spec)
		}
		if nativeErr == nil && s.metrics != nil {
			stat, e := s.runtime.Statistics(ctx, spec)
			if e == nil {
				sample = &stat
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
			if current.Operation != "delete" {
				current.Status = "failed"
			}
			current.Deployment = engine.Deployment{}
			current.Version++
			current.Due = s.clock.Now().Add(healthInterval)
			return tx.PutCluster(current)
		}
		if current.Operation == "delete" {
			if e = s.publish(tx.Context(), current.Key, "deleted", current.Operation); e != nil {
				return e
			}
			if e = tx.DeleteCluster(k); e != nil {
				return e
			}
			return settleAccess(tx, k.Scope)
		}
		current.Status = "available"
		current.Deployment = deployment
		current.RestoreSnapshot = ""
		current.Due = s.clock.Now().Add(healthInterval)
		current.Version++
		if current.Operation != "" && current.Operation != "reconcile" {
			if e = s.publish(tx.Context(), current.Key, current.Status, current.Operation); e != nil {
				return e
			}
		}
		current.Operation = ""
		if e = tx.PutCluster(current); e != nil {
			return e
		}
		if e = settleAccess(tx, k.Scope); e != nil {
			return e
		}
		if sample != nil {
			return s.publishMetrics(tx.Context(), current, *sample)
		}
		return nil
	})
}
func settleAccess(tx Transaction, sc Scope) error {
	all, e := tx.Clusters(sc)
	if e != nil {
		return e
	}
	for _, v := range all {
		if v.Status != "available" {
			return nil
		}
	}
	users, e := tx.Users(sc)
	if e != nil {
		return e
	}
	for _, u := range users {
		if u.Status == "deleting" {
			if e = tx.DeleteUser(u.Key); e != nil {
				return e
			}
		} else if u.Status == "modifying" {
			u.Status = "active"
			if e = tx.PutUser(u); e != nil {
				return e
			}
		}
	}
	acls, e := tx.ACLs(sc)
	if e != nil {
		return e
	}
	for _, a := range acls {
		if a.Status == "modifying" {
			a.Status = "active"
			if e = tx.PutACL(a); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Service) publish(ctx context.Context, k Key, status, operation string) error {
	if s.events == nil {
		return nil
	}
	return s.events.PublishMemoryDBEvent(ctx, Event{ARN: k.ARN(), Name: k.Name, Kind: k.Kind, Status: status, Operation: operation, At: s.clock.Now()})
}
func (s *Service) publishMetrics(ctx context.Context, c Cluster, stat engine.Statistics) error {
	for _, sample := range []struct {
		name  string
		value int64
	}{{"CurrConnections", stat.Connections}, {"BytesUsedForMemoryDB", stat.UsedMemory}} {
		if e := s.metrics.PublishMemoryDBMetric(ctx, Metric{ARN: c.Key.ARN(), ClusterName: c.Key.Name, Name: sample.name, Value: float64(sample.value), At: s.clock.Now()}); e != nil {
			return e
		}
	}
	return nil
}
