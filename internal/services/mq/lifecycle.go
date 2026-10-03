package mq

import (
	"context"
	"errors"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

// Start fences stale endpoints until the exact owned native broker is observed.
func (s *Service) Start() error {
	err := s.repository.Update(context.Background(), func(t Transaction) error {
		rows, e := t.AllBrokers()
		if e != nil {
			return e
		}
		for _, v := range rows {
			if v.State == "RUNNING" {
				v.State = "REBOOT_IN_PROGRESS"
				v.Operation = "reconcile"
				v.Endpoint = Endpoint{}
				v.Version++
				v.Due = s.clock.Now()
				if e = t.PutBroker(v); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.jobs.Start()
	return nil
}

type brokerJobs struct{ s *Service }

func (j brokerJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		rows, e := r.AllBrokers()
		if e != nil {
			return e
		}
		for _, v := range rows {
			if v.State == "RUNNING" && (v.Logs.General || v.Logs.Audit) && !v.LogDue.IsZero() {
				job := scheduler.Job{Key: "logs:" + v.ARN, Version: v.Version, Due: v.LogDue}
				if !found || scheduler.Compare(job, next) < 0 {
					next = job
					found = true
				}
			}
			if v.Due.IsZero() {
				continue
			}
			job := scheduler.Job{Key: v.ARN, Version: v.Version, Due: v.Due}
			if !found || scheduler.Compare(job, next) < 0 {
				next = job
				found = true
			}
		}
		return nil
	})
	return next, found, err
}
func (j brokerJobs) Run(ctx context.Context, job scheduler.Job) error {
	if strings.HasPrefix(job.Key, "logs:") {
		return j.runLogs(ctx, job)
	}
	p := strings.Split(job.Key, ":")
	if len(p) != 8 {
		return errors.New("invalid retained MQ job ARN")
	}
	sc := Scope{p[1], p[4], p[3]}
	var v BrokerRecord
	err := j.s.repository.View(ctx, func(r Reader) error { var e error; v, e = r.Broker(sc, p[7]); return e })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s := j.s
	if v.Version != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
		return nil
	}
	// Claim maintenance work before leaving the transaction domain. User/config
	// admissions increment Version, so an older probe cannot consume new intent.
	if v.State == "RUNNING" && (hasPending(v) || v.MaintenanceAdjustments > 0) && !v.MaintenanceDue.IsZero() && !v.MaintenanceDue.After(s.clock.Now()) {
		return s.repository.Update(ctx, func(t Transaction) error {
			current, err := t.Broker(v.Scope, v.ID)
			if err != nil {
				return err
			}
			if current.Version != v.Version || current.State != "RUNNING" {
				return nil
			}
			current.State, current.Operation = "REBOOT_IN_PROGRESS", "maintenance"
			current.Version++
			current.Due = s.clock.Now()
			current.Endpoint = Endpoint{}
			return t.PutBroker(current)
		})
	}
	effective := v
	if v.Operation == "reboot" || v.Operation == "maintenance" {
		effective = applyPending(v)
	}
	var endpoint Endpoint
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native MQ runtime is unavailable")
	} else {
		switch v.Operation {
		case "delete":
			nativeErr = s.runtime.Delete(ctx, v)
		case "reboot", "maintenance":
			endpoint, nativeErr = s.runtime.Reboot(ctx, effective)
		default:
			endpoint, nativeErr = s.runtime.Ensure(ctx, v)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var observed BrokerRecord
	committed := false
	err = s.repository.Update(ctx, func(t Transaction) error {
		current, e := t.Broker(v.Scope, v.ID)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Version != v.Version || current.Operation != v.Operation || current.State != v.State || current.Endpoint.NativeID != v.Endpoint.NativeID || !current.Due.Equal(v.Due) {
			return nil
		}
		if nativeErr != nil {
			current.Failure = nativeErr.Error()
			current.Endpoint = Endpoint{}
			if current.Operation == "create" {
				current.State = "CREATION_FAILED"
			} else if current.Operation != "delete" {
				current.State = "CRITICAL_ACTION_REQUIRED"
			}
			current.Due = s.clock.Now().Add(30 * time.Second)
			return t.PutBroker(current)
		}
		if current.Operation == "delete" {
			return t.DeleteBroker(current.Scope, current.ID)
		}
		if endpoint.Address == "" || endpoint.NativeID == "" || len(endpoint.CAPEM) == 0 {
			return errors.New("native broker readiness omitted endpoint, identity or TLS CA")
		}
		current.Endpoint = endpoint
		current.State = "RUNNING"
		current.Operation = ""
		if v.Operation == "reboot" || v.Operation == "maintenance" {
			current.Users = effective.Users
			current.Configuration = effective.Configuration
			current.PendingConfiguration = ConfigurationReference{}
			current.ConfigurationHistory = effective.ConfigurationHistory
			current.Logs = effective.Logs
			current.PendingLogs = nil
			if v.Operation == "maintenance" {
				current.MaintenanceAdjustments = 0
			}
			if current.MaintenanceAdjustments == 0 {
				current.MaintenanceDue = time.Time{}
			}
			current.Username, current.Password = "", ""
		}
		if current.Logs.General || current.Logs.Audit {
			if current.LogDue.IsZero() {
				current.LogDue = s.clock.Now()
			}
		} else {
			current.LogDue = time.Time{}
			current.LogDeliveryError = ""
		}
		current.Failure = ""
		current.Due = s.clock.Now().Add(30 * time.Second)
		if !current.MaintenanceDue.IsZero() && current.MaintenanceDue.Before(current.Due) {
			current.Due = current.MaintenanceDue
		}
		if e = t.PutBroker(current); e != nil {
			return e
		}
		observed, committed = current, true
		return nil
	})
	if err != nil || !committed {
		return err
	}
	// Native readiness and its next retained deadline commit independently of
	// CloudWatch. A failed observation retries only on the next reconciliation.
	return s.deliverMetrics(ctx, observed)
}
