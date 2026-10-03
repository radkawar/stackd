package rds

import (
	"context"
	"errors"
	"strings"
	"time"

	engine "stackd/engine/rds"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

const healthInterval = 30 * time.Second

// Start distrusts retained endpoints until the actual native process has been
// reattached and authenticated. It never starts a second controller loop.
func (s *Service) Start() error {
	e := s.repository.Update(context.Background(), func(tx Transaction) error {
		all, e := tx.AllDatabases()
		if e != nil {
			return e
		}
		for _, v := range all {

			if v.Cluster != "" {
				continue
			}
			if v.Status == "available" {

				v.Status = "starting"
				v.Endpoint = engine.Endpoint{}
				v.Operation = "reconcile"
				v.Due = s.clock.Now()
				v.Version++
				if e = tx.PutDatabase(v); e != nil {
					return e
				}
				if v.Key.Kind == "cluster" {
					if e = s.mirrorMembers(tx, v); e != nil {
						return e
					}
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

func (s *Service) specification(ctx context.Context, v Database) (engine.Specification, error) {
	if e := s.ensureRuntime(); e != nil {
		return engine.Specification{}, e
	}
	user, password, e := s.cipher.Open(ctx, v.Key.ARN(), v.Ciphertext)
	if e != nil {
		return engine.Specification{}, e
	}
	return engine.Specification{ID: v.RuntimeID, Engine: v.Engine, Database: v.DatabaseName, Username: user, Password: password, Port: v.RequestedPort, Parameters: v.Parameters}, nil
}

func jobKey(raw string) (Key, error) {
	p := strings.SplitN(raw, ":", 7)
	if len(p) != 7 || p[0] != "arn" || p[2] != "rds" {
		return Key{}, errors.New("invalid retained RDS job key")
	}
	return Key{Scope: Scope{p[1], p[4], p[3]}, Kind: p[5], Name: p[6]}, nil
}

func eligibleDatabase(v Database) bool {
	return v.Cluster == "" && !v.Due.IsZero()
}

type databaseJobs struct {
	s *Service
}

func (j databaseJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := j.s.repository.View(ctx, func(r Reader) error {
		all, e := r.AllDatabases()
		if e != nil {
			return e
		}
		for _, v := range all {

			if !eligibleDatabase(v) {
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

func (j databaseJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	k, e := jobKey(job.Key)
	if e != nil {
		return e
	}
	ctx = runtimeContext(ctx, k)
	var v Database
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		v, e = r.Database(k)
		return e
	})
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if !eligibleDatabase(v) || uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
		return nil
	}
	var endpoint engine.Endpoint
	var sample *engine.Statistics
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native RDS runtime unavailable")
	} else {
		switch v.Operation {

		case "delete":
			nativeErr = s.runtime.Delete(ctx, v.RuntimeID)
		case "stop", "detach":
			nativeErr = s.runtime.Stop(ctx, v.RuntimeID)
		default:
			spec, err := s.specification(ctx, v)
			nativeErr = err
			if nativeErr == nil {

				if v.Operation == "password" {

					_, password, err := s.cipher.Open(ctx, v.Key.ARN(), v.PendingCiphertext)
					nativeErr = err
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
				if nativeErr == nil && s.metrics != nil {
					if stat, err := s.runtime.Statistics(ctx, spec); err == nil {
						sample = &stat
					}
				}

			}

		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	committed := false
	e = s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Database(k)
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
			if e = tx.PutDatabase(current); e != nil {
				return e
			}
			if k.Kind == "cluster" {
				return s.mirrorMembers(tx, current)
			}
			return nil

		}
		if current.Operation == "delete" {

			current.Status = "deleted"
			if e = s.publishTransition(tx.Context(), current, "Database deleted"); e != nil {
				return e
			}
			return tx.DeleteDatabase(k)

		}
		if current.Operation == "detach" {

			all, e := tx.Databases(k.Scope)
			if e != nil {
				return e
			}
			for _, m := range all {
				if m.Cluster == k.Name && m.Status == "deleting" {

					m.Status = "deleted"
					m.Operation = "delete"
					if e = s.publishTransition(tx.Context(), m, "DB instance deleted"); e != nil {
						return e
					}
					if e = tx.DeleteDatabase(m.Key); e != nil {
						return e
					}

				}
			}
			current.Status = "creating"
			current.Endpoint = engine.Endpoint{}
			current.Due = time.Time{}
			current.Operation = ""
			current.Version++
			return tx.PutDatabase(current)

		}
		if current.Operation == "stop" {

			current.Status = "stopped"
			current.Endpoint = engine.Endpoint{}
			current.Due = time.Time{}

		} else {

			current.Status = "available"
			current.Endpoint = endpoint
			current.Due = s.clock.Now().Add(healthInterval)
			if current.Operation == "start" || current.Operation == "reboot" || current.Operation == "create" || current.Operation == "restore" {
				current.PendingParameters = false
			}
			if current.Operation == "password" {

				current.Ciphertext = current.PendingCiphertext
				current.PendingCiphertext = nil

			}
			current.RestoreSnapshot = ""

		}
		if current.Operation != "" && current.Operation != "reconcile" {
			if e = s.publishTransition(tx.Context(), current, "Database lifecycle completed"); e != nil {
				return e
			}
		}
		current.Operation = ""
		current.Version++
		if e = tx.PutDatabase(current); e != nil {
			return e
		}
		if k.Kind == "cluster" {
			if e = s.mirrorMembers(tx, current); e != nil {
				return e
			}
		}
		committed = true
		return nil
	})
	if e != nil || !committed || sample == nil {
		return e
	}
	// A CloudWatch failure cannot roll back a successfully reconciled database.
	// This sampled gauge is retried by the next genuine periodic observation.
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Database(k)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.RuntimeID != v.RuntimeID || current.Status != "available" {
			return nil
		}
		identifier, arn := k.Name, k.ARN()
		if k.Kind == "cluster" {

			all, e := tx.Databases(k.Scope)
			if e != nil {
				return e
			}
			identifier = ""
			for _, m := range all {
				if m.Cluster == k.Name && m.Status == "available" {

					identifier, arn = m.Key.Name, m.Key.ARN()
					break

				}
			}

		}
		if identifier == "" {
			return nil
		}
		return s.metrics.PublishRDSMetric(tx.Context(), RDSMetric{ARN: arn, Identifier: identifier, Name: "DatabaseConnections", Value: float64(sample.Connections), At: s.clock.Now()})
	})
}

// observeDatabase only probes a previously published endpoint. It never creates
// or starts a process and never holds a repository transaction during native I/O.
func (s *Service) observeDatabase(ctx context.Context, v Database) error {
	if v.Status != "available" || v.Cluster != "" {
		return nil
	}
	ctx = runtimeContext(ctx, v.Key)
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	spec, e := s.specification(probe, v)
	if e == nil {

		db, err := engine.Open(probe, v.Engine, v.Endpoint, v.DatabaseName, spec.Username, spec.Password)
		e = err
		if db != nil {
			_ = db.Close()
		}

	}
	if e == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Database(v.Key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Version != v.Version || current.RuntimeID != v.RuntimeID || current.Status != "available" {
			return nil
		}
		current.Status = "starting"
		current.Endpoint = engine.Endpoint{}
		current.Operation = "reconcile"
		current.Version++
		current.Due = s.clock.Now()
		if e = tx.PutDatabase(current); e != nil {
			return e
		}
		if current.Key.Kind == "cluster" {
			return s.mirrorMembers(tx, current)
		}
		return nil
	})
}

func (s *Service) observeScope(ctx context.Context) error {
	var all []Database
	e := s.repository.View(ctx, func(r Reader) error {
		var e error
		all, e = r.Databases(scopeFor(ctx))
		return e
	})
	if e != nil {
		return e
	}
	for _, v := range all {
		if e = s.observeDatabase(ctx, v); e != nil {
			return e
		}
	}
	return nil
}
