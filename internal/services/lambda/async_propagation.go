package lambda

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/scheduler"
)

// The native paired capture in event_config_timing.json observed early retries
// after Get returned zero, then single attempts for events accepted 152s later.
// Two minutes is our deterministic representative, not an AWS latency guarantee.
const eventInvokeConfigPropagation = 2 * time.Minute

func (s *Service) stageEventInvokeConfig(tx Transaction, v *EventInvokeConfig) error {
	v.Modified = s.clock.Now()
	v.Version++
	v.AppliesAt = nil
	desired := configuredEventInvokeSettings(*v)
	if desired != v.Effective {
		due := v.Modified.Add(eventInvokeConfigPropagation)
		v.AppliesAt = &due
	} else if v.Deleted {
		if err := tx.ReattachInvocationSettings(v.Key); err != nil {
			return err
		}
		return tx.DeleteEventInvokeConfig(v.Key)
	}
	return tx.PutEventInvokeConfig(*v)
}

type eventInvokeConfigJobs struct{ s *Service }

func (j eventInvokeConfigJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	s := j.s
	enabled := s.started.Load() && !s.closed.Load()
	if !enabled {
		return scheduler.Job{}, false, nil
	}
	var job scheduler.Job
	var found bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		job, found, err = r.NextEventInvokeConfigChange()
		return err
	})
	return job, found, err
}

func (j eventInvokeConfigJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil {
		return err
	}
	name, qualifier, _ := strings.Cut(strings.TrimPrefix(parsed.Resource, "function:"), ":")
	key := FunctionReference{FunctionKey: FunctionKey{Scope: Scope{Partition: parsed.Partition, Account: parsed.AccountID, Region: parsed.Region}, Name: name}, Qualifier: qualifier}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.EventInvokeConfig(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Version != job.Version || v.AppliesAt == nil || v.AppliesAt.After(j.s.clock.Now()) {
			return nil
		}
		if err := tx.ReattachInvocationSettings(key); err != nil {
			return err
		}
		if v.Deleted {
			return tx.DeleteEventInvokeConfig(key)
		}
		v.Effective = configuredEventInvokeSettings(v)
		v.AppliesAt = nil
		return tx.PutEventInvokeConfig(v)
	})
}
