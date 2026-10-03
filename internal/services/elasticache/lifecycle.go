package elasticache

import (
	"context"
	"errors"
	"slices"
	engine "stackd/engine/valkey"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

const healthInterval = 30 * time.Second

func (s *Service) Start() error {
	e := s.repository.Update(context.Background(), func(tx Transaction) error {
		all, e := tx.AllClusters()
		if e != nil {
			return e
		}
		for _, v := range all {
			if v.Status == "available" {
				v.Nodes = nil
				if e = s.markCluster(tx, v, "reconcile", "modifying"); e != nil {
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
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, InvokedBy: "elasticache.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "elasticache.amazonaws.com", SourceARN: k.ARN()}})
}
func jobKey(raw string) (Key, error) {
	p := strings.SplitN(raw, ":", 7)
	if len(p) != 7 || p[0] != "arn" || p[2] != "elasticache" {
		return Key{}, errors.New("invalid retained ElastiCache job key")
	}
	return Key{Scope: Scope{p[1], p[4], p[3]}, Kind: p[5], Name: p[6]}, nil
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
				next, found = candidate, true
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
	waiting := false
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		v, e = r.Cluster(k)
		if e != nil {
			return e
		}
		if uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
			return nil
		}
		if v.Operation == "delete-after-snapshot" {
			snaps, e := r.Snapshots(k.Scope)
			if e != nil {
				return e
			}
			for _, snap := range snaps {
				if snap.SourceRuntimeID == v.RuntimeID && snap.Status != "available" {
					waiting = true
				}
			}
		}
		if v.Operation != "delete" && v.Operation != "delete-after-snapshot" {
			spec, e = s.specification(r, v)
		}
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
	if waiting {
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
		nativeErr = errors.New("native cache runtime unavailable")
	} else {
		switch v.Operation {
		case "delete", "delete-after-snapshot":
			nativeErr = s.runtime.Delete(ctx, v.RuntimeID)
		case "reboot":
			deployment, nativeErr = s.runtime.Restart(ctx, spec)
		default:
			if v.RestoreSnapshot != "" {
				deployment, nativeErr = s.runtime.Restore(ctx, spec, v.RestoreSnapshot)
			} else {
				deployment, nativeErr = s.runtime.Ensure(ctx, spec)
			}
		}
		if nativeErr == nil && v.Operation != "delete" && v.Operation != "delete-after-snapshot" && s.metrics != nil {
			stat, err := s.runtime.Statistics(ctx, spec)
			if err == nil {
				sample = &stat
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	committed := false
	e = s.repository.Update(ctx, func(tx Transaction) error {
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
			current.Nodes = nil
			if current.Status != "deleting" {
				current.Status = "create-failed"
			}
			current.Version++
			current.Due = s.clock.Now().Add(healthInterval)
			return tx.PutCluster(current)
		}
		if current.Operation == "delete" || current.Operation == "delete-after-snapshot" {
			if e = tx.DeleteCluster(k); e != nil {
				return e
			}
			return s.finishACL(tx, k.Scope)
		}
		current.Nodes = deployment.Nodes
		current.Status = "available"
		current.Operation = ""
		current.RestoreSnapshot = ""
		current.Version++
		current.Due = s.clock.Now().Add(healthInterval)
		if e = tx.PutCluster(current); e != nil {
			return e
		}
		if e = s.finishACL(tx, k.Scope); e != nil {
			return e
		}
		committed = true
		return nil
	})
	if e != nil || !committed || sample == nil {
		return e
	}
	return s.publishStatistics(ctx, v, *sample)
}
func (s *Service) finishACL(tx Transaction, scope Scope) error {
	groups, e := tx.UserGroups(scope)
	if e != nil {
		return e
	}
	all, e := tx.Clusters(scope)
	if e != nil {
		return e
	}
	pendingGroups := map[string]bool{}
	for _, v := range all {
		if v.UserGroup != "" && v.Status != "available" {
			pendingGroups[v.UserGroup] = true
		}
	}
	pendingUsers := map[string]bool{}
	for _, g := range groups {
		if pendingGroups[g.Key.Name] {
			for _, id := range g.UserIDs {
				pendingUsers[id] = true
			}
		} else if g.Status == "modifying" {
			g.Status = "active"
			if e = tx.PutUserGroup(g); e != nil {
				return e
			}
		}
	}
	users, e := tx.Users(scope)
	if e != nil {
		return e
	}
	for _, u := range users {
		if u.Status == "modifying" && !pendingUsers[u.Key.Name] {
			u.Status = "active"
			if e = tx.PutUser(u); e != nil {
				return e
			}
		}
		if u.Status == "deleting" && !pendingUsers[u.Key.Name] {
			for _, original := range groups {
				if !slices.Contains(original.UserIDs, u.Key.Name) {
					continue
				}
				g, err := tx.UserGroup(original.Key)
				if err != nil {
					return err
				}
				g.UserIDs = slices.DeleteFunc(g.UserIDs, func(id string) bool { return id == u.Key.Name })
				if e = tx.PutUserGroup(g); e != nil {
					return e
				}
			}
			if e = tx.DeleteUser(u.Key); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Service) publishStatistics(ctx context.Context, v Cluster, stat engine.Statistics) error {
	for _, sample := range []struct {
		name  string
		value int64
	}{{"CurrConnections", stat.Connections}, {"BytesUsedForCache", stat.UsedMemory}} {
		if e := s.metrics.PublishElastiCacheMetric(ctx, Metric{ARN: v.Key.ARN(), Identifier: v.Key.Name, Name: sample.name, Value: float64(sample.value), At: s.clock.Now()}); e != nil {
			return e
		}
	}
	return nil
}

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
	var source Cluster
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
			source, e = r.Cluster(Key{Scope: k.Scope, Kind: v.SourceKind, Name: v.Source})
			if e != nil {
				return e
			}
			if source.RuntimeID != v.SourceRuntimeID {
				return errors.New("snapshot source incarnation changed")
			}
			spec, e = s.specification(r, source)
		}
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
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native cache runtime unavailable")
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
			current.Version++
			current.Due = s.clock.Now().Add(healthInterval)
			return tx.PutSnapshot(current)
		}
		if current.Operation == "delete" {
			return tx.DeleteSnapshot(k)
		}
		current.Status = "available"
		current.Operation = ""
		current.CopySource = ""
		current.Version++
		current.Due = time.Time{}
		if e = tx.PutSnapshot(current); e != nil {
			return e
		}
		if v.Operation == "snapshot" {
			cluster, e := tx.Cluster(source.Key)
			if e != nil {
				return e
			}
			if cluster.RuntimeID == source.RuntimeID && cluster.Status == "snapshotting" {
				cluster.Status = "available"
				cluster.Due = s.clock.Now().Add(healthInterval)
				cluster.Version++
				return tx.PutCluster(cluster)
			}
		}
		return nil
	})
}
