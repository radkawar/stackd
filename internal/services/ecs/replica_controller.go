package ecs

import (
	"context"
	"errors"
	"log/slog"
	"stackd/internal/awsctx"
	"time"
)

type replicaExecution struct {
	service *Service
	key     ServiceKey
	ctx     context.Context
	wakeups chan struct{}
	metrics replicaMetrics
}

// The shared dispatcher routes committed intents; each replica owner serializes
// its own scheduling decisions and uses the service clock for deadline recovery.
func (c *taskController) dispatchServices() error {
	var keys []ServiceKey
	if err := c.service.repository.View(c.ctx, func(r Reader) error { var err error; keys, err = r.ActiveServiceKeys(); return err }); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		e, exists := c.replicas[key]
		if !exists {
			e = &replicaExecution{service: c.service, key: key, ctx: c.ctx, wakeups: make(chan struct{}, 1)}
			c.replicas[key] = e
			c.work.Add(1)
			go func() {
				defer c.work.Done()
				e.run()
				c.mu.Lock()
				delete(c.replicas, e.key)
				c.mu.Unlock()
				c.wake()
			}()
		}
		select {
		case e.wakeups <- struct{}{}:
		default:
		}
	}
	return nil
}
func (e *replicaExecution) run() {
	for e.ctx.Err() == nil {
		active := true
		changed := false
		deadline := e.service.clock.Now().Add(time.Second)
		var record ServiceRecord
		targetHealth, healthErr := e.service.serviceTargetHealth(e.ctx, e.key)
		err := e.service.repository.Update(e.ctx, func(tx Transaction) error {
			var err error
			record, err = tx.Service(e.key)
			if errors.Is(err, ErrNotFound) {
				active = false
				return nil
			}
			if err != nil {
				return err
			}
			if value(record.Data.Status) == "INACTIVE" {
				active = false
				return nil
			}
			if healthErr != nil && value(record.Data.Status) == "ACTIVE" {
				return healthErr
			}
			ctx := serviceOwnerContext(tx.Context(), record)
			changed, err = e.service.reconcileService(ctx, tx, &record, targetHealth)
			active = value(record.Data.Status) != "INACTIVE"
			for _, deployment := range record.Deployments {
				for _, at := range []time.Time{deployment.Deadline, deployment.RetryAfter} {
					if !at.IsZero() && at.After(e.service.clock.Now()) && at.Before(deadline) {
						deadline = at
					}
				}
			}
			if !record.DrainAfter.IsZero() && record.DrainAfter.After(e.service.clock.Now()) && record.DrainAfter.Before(deadline) {
				deadline = record.DrainAfter
			}
			return err
		})
		if err != nil && e.ctx.Err() == nil {
			slog.Error("ECS service reconciliation failed", "service", e.key.ARN(), "error", err)
		}
		if changed {
			e.service.tasks.wake()
		}
		if !active {
			return
		}
		if err == nil {
			nextMetric, err := e.metrics.collect(e.ctx, e.service, record)
			if err != nil && e.ctx.Err() == nil {
				slog.Error("ECS service metric collection failed", "service", e.key.ARN(), "error", err)
			}
			if !nextMetric.IsZero() && nextMetric.Before(deadline) {
				deadline = nextMetric
			}
		}
		timer := e.service.clock.NewTimerAt(deadline)
		select {
		case <-e.ctx.Done():
			timer.Stop()
			return
		case <-e.wakeups:
			timer.Stop()
		case <-timer.C():
		}
	}
}
func serviceOwnerContext(ctx context.Context, record ServiceRecord) context.Context {
	k := record.Key
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ParentEventID: record.AcceptedEventID, InvokedBy: ServicePrincipal, SourceIP: ServicePrincipal, UserAgent: ServicePrincipal})
}
