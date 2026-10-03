package eks

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	native "stackd/compute/eks"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// Start reattaches retained clusters without deleting native workloads on controller exit.
func (s *Service) Start() error {
	s.effects.mu.Lock()
	if s.effects.closed {
		s.effects.mu.Unlock()
		return errors.New("EKS service is closed")
	}
	if s.effects.started {
		s.effects.mu.Unlock()
		return nil
	}
	s.effects.started = true
	s.effects.mu.Unlock()
	e := s.repository.Update(s.effects.ctx, func(tx Transaction) error {
		all, e := tx.AllClusters()
		if e != nil {
			return e
		}
		for _, c := range all {
			if c.Status == "ACTIVE" {
				c.Operation = "reconcile"
				c.Due = s.clock.Now()
				c.Generation++
				if e = tx.PutCluster(c); e != nil {
					return e
				}
			}
		}
		if e = s.startNodegroups(tx); e != nil {
			return e
		}
		return s.startComponents(tx)
	})
	if e != nil {
		s.effects.mu.Lock()
		s.effects.started = false
		s.effects.mu.Unlock()
		return e
	}
	s.jobs.Start()
	return nil
}

// Each cluster has one in-memory effect owner. Durable pending work stays in the
// cluster row; k3d must never hold the scheduler's shared cross-service drain.
type clusterEffects struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	work            sync.WaitGroup
	active          map[Key]struct{}
	nodegroups      map[NodegroupKey]struct{}
	started, closed bool
}

func newClusterEffects() *clusterEffects {
	ctx, cancel := context.WithCancel(context.Background())
	return &clusterEffects{ctx: ctx, cancel: cancel, active: make(map[Key]struct{}), nodegroups: make(map[NodegroupKey]struct{})}
}

func (s *Service) Close() error {
	s.effects.mu.Lock()
	s.effects.closed = true
	s.effects.cancel()
	s.effects.mu.Unlock()
	s.jobs.Close()
	s.effects.work.Wait()
	return nil
}

type clusterJobs struct{ s *Service }

func (j clusterJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := j.s.repository.View(ctx, func(tx Reader) error {
		all, e := tx.AllClusters()
		if e != nil {
			return e
		}
		j.s.effects.mu.Lock()
		defer j.s.effects.mu.Unlock()
		if j.s.effects.closed {
			return nil
		}
		for _, c := range all {
			_, active := j.s.effects.active[c.Key]
			if active || c.Due.IsZero() {
				continue
			}
			candidate := scheduler.Job{Key: c.Key.ARN(), Version: uint64(c.Generation), Due: c.Due}
			if !found || scheduler.Compare(candidate, next) < 0 {
				next = candidate
				found = true
			}
		}
		return nil
	})
	if e != nil {
		return next, found, e
	}
	candidate, hasNodegroup, e := j.s.nodegroupNext(ctx)
	if e != nil {
		return next, found, e
	}
	if hasNodegroup && (!found || scheduler.Compare(candidate, next) < 0) {
		return candidate, true, nil
	}
	return next, found, nil
}
func (j clusterJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	if strings.HasPrefix(job.Key, "eks-nodegroup:") {
		return s.runNodegroupJob(ctx, job)
	}
	k, e := parseClusterARN(job.Key)
	if e != nil {
		return e
	}
	var c Cluster
	e = s.repository.View(ctx, func(tx Reader) error { var e error; c, e = tx.Cluster(k); return e })
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if uint64(c.Generation) != job.Version || !c.Due.Equal(job.Due) || c.Due.After(s.clock.Now()) {
		return nil
	}
	s.effects.mu.Lock()
	defer s.effects.mu.Unlock()
	if s.effects.closed {
		return nil
	}
	if _, active := s.effects.active[k]; active {
		return nil
	}
	s.effects.active[k] = struct{}{}
	s.effects.work.Go(func() {
		effectCtx := awsctx.WithMetadata(s.effects.ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, InvokedBy: "eks.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "eks.amazonaws.com", SourceARN: k.ARN()}})
		if err := s.runCluster(effectCtx, c); err != nil && effectCtx.Err() == nil {
			slog.ErrorContext(effectCtx, "EKS native completion failed", "cluster", k.ARN(), "error", err)
		}
		s.effects.mu.Lock()
		delete(s.effects.active, k)
		s.effects.mu.Unlock()
		s.jobs.Wake()
	})
	return nil
}

func (s *Service) runCluster(ctx context.Context, c Cluster) error {
	k := c.Key
	var endpoint native.Endpoint
	var nativeErr error
	desired := c
	updateID := strings.TrimPrefix(c.Operation, "update:")
	updating := strings.HasPrefix(c.Operation, "update:")
	loggingUpdate := false
	if updating {
		err := s.repository.View(ctx, func(tx Reader) error {
			u, err := tx.ClusterUpdate(c.Key, updateID)
			if err != nil {
				return err
			}
			if u.KubernetesVersion != "" {
				desired.KubernetesVersion = u.KubernetesVersion
			}
			if u.EnabledLogTypes != nil {
				loggingUpdate = true
				desired.EnabledLogTypes = u.EnabledLogTypes
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if s.runtime == nil {
		nativeErr = errors.New("kubernetes runtime is unavailable")
	} else if c.Operation == "delete" {
		nativeErr = s.runtime.Delete(ctx, c.ID)
	} else {
		endpoint, nativeErr = s.runtime.Ensure(ctx, native.Specification{
			ID: c.ID, Version: desired.KubernetesVersion, Logging: c.EnabledLogTypes,
			LogSink: s.runtimeLogSink(c), PodIdentityHandler: s.PodIdentityHandler(c.Key, c.ID),
			AuditSink:            s.runtimeAuditSink(c),
			PodIdentityEndpoint:  s.podIdentityEndpoint,
			ServiceAccountIssuer: c.ServiceAccountIssuer(), Region: c.Key.Region,
			FargateAuthorize: func(ctx context.Context, profileID string) error {
				return s.authorizeFargatePod(ctx, c.Key, profileID)
			},
			FargateProfiles: func(ctx context.Context) ([]native.FargateSpecification, error) {
				return s.runtimeFargateProfiles(ctx, c.Key)
			},
		}, s.kubernetesHandler(c.Key, c.ID))
		if nativeErr == nil {
			nativeErr = s.reconcileComponents(ctx, desired)
		}
		if nativeErr == nil && loggingUpdate {
			// Apply the candidate last. Failed preparation or component
			// reconciliation must not change the committed live log mask.
			if logging, ok := s.runtime.(native.LoggingRuntime); ok {
				nativeErr = logging.ConfigureControlPlaneLogging(ctx, c.ID, desired.EnabledLogTypes, s.runtimeLogSink(desired))
			} else {
				nativeErr = errors.New("native control plane logging configuration is unavailable")
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
		if current.ID != c.ID || current.Generation != c.Generation || current.Operation != c.Operation {
			return nil
		}
		if c.Operation == "delete" && nativeErr == nil {
			return tx.DeleteCluster(k)
		}
		current.Generation++
		var pending *native.UpgradePendingError
		if errors.As(nativeErr, &pending) && updating {
			current.Error = nativeErr.Error()
			current.Due = s.clock.Now().Add(30 * time.Second)
			return tx.PutCluster(current)
		}
		current.Due = time.Time{}
		current.Operation = ""
		current.Error = ""
		if updating {
			u, e := tx.ClusterUpdate(k, updateID)
			if e != nil {
				return e
			}
			if nativeErr != nil {
				u.Status = "Failed"
				u.ErrorCode = "ClusterUnreachable"
				u.ErrorMessage = nativeErr.Error()
			} else {
				u.Status = "Successful"
				if u.DeletionProtection != nil {
					current.DeletionProtection = *u.DeletionProtection
				}
				if u.AuthenticationMode != "" {
					if current.AuthenticationMode == "CONFIG_MAP" {
						if e = s.createBootstrapEntry(tx, current); e != nil {
							return e
						}
					}
					current.AuthenticationMode = u.AuthenticationMode
				}
				if u.KubernetesVersion != "" {
					current.KubernetesVersion = u.KubernetesVersion
				}
				if u.EnabledLogTypes != nil {
					current.EnabledLogTypes = u.EnabledLogTypes
				}
			}
			if e = tx.PutClusterUpdate(u); e != nil {
				return e
			}
		}
		if nativeErr != nil {
			current.Error = nativeErr.Error()
			if c.Operation == "delete" {
				current.Status = "DELETING"
				current.Operation = "delete"
				current.Due = s.clock.Now().Add(30 * time.Second)
			} else if c.Status == "UPDATING" || c.Status == "ACTIVE" {
				current.Status = "ACTIVE"
				if c.Status == "ACTIVE" {
					current.Operation = "reconcile"
					current.Due = s.clock.Now().Add(30 * time.Second)
				}
			} else {
				current.Status = "FAILED"
			}
		} else {
			current.Status = "ACTIVE"
			current.Endpoint = endpoint.URL
			current.CertificateAuthority = endpoint.CertificateAuthority
			next, err := nextComponentDue(tx, current.Key)
			if err != nil {
				return err
			}
			if !next.IsZero() {
				current.Operation = "components"
				current.Due = next
			}
		}
		return tx.PutCluster(current)
	})
}
func parseClusterARN(raw string) (Key, error) {
	p := strings.SplitN(raw, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[2] != "eks" || !strings.HasPrefix(p[5], "cluster/") {
		return Key{}, invalid("Invalid cluster ARN.")
	}
	name := strings.TrimPrefix(p[5], "cluster/")
	if !clusterName.MatchString(name) {
		return Key{}, invalid("Invalid cluster ARN.")
	}
	return Key{Scope{p[1], p[4], p[3]}, name}, nil
}
