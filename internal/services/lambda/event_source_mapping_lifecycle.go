package lambda

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/scheduler"
)

type eventSourceMappingJobs struct{ s *Service }

func (j eventSourceMappingJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error {
		rows, err := r.AllEventSourceMappings()
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.TransitionAt.IsZero() {
				continue
			}
			candidate := scheduler.Job{Key: v.Key.ARN(), Version: v.Version, Due: v.TransitionAt}
			if !found || scheduler.Compare(candidate, job) < 0 {
				job, found = candidate, true
			}
		}
		return nil
	})
	return
}

func (j eventSourceMappingJobs) Run(ctx context.Context, job scheduler.Job) error {
	p, err := arn.Parse(job.Key)
	if err != nil {
		return err
	}
	key := EventSourceMappingKey{Scope: Scope{Partition: p.Partition, Account: p.AccountID, Region: p.Region}, UUID: strings.TrimPrefix(p.Resource, "event-source-mapping:")}
	var retiring EventSourceMappingRecord
	err = j.s.repository.View(ctx, func(r Reader) error {
		v, err := r.EventSourceMapping(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.State == "Deleting" && v.Version == job.Version && v.TransitionAt.Equal(job.Due) && !job.Due.After(j.s.clock.Now()) {
			retiring = v
		}
		return nil
	})
	if err != nil {
		return err
	}
	if retiring.State == "Deleting" {
		if err := j.s.releaseMappingNetwork(ctx, retiring); err != nil {
			return err
		}
	}
	changed := false
	err = j.s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.EventSourceMapping(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Version != job.Version || !v.TransitionAt.Equal(job.Due) || job.Due.After(j.s.clock.Now()) {
			return nil
		}
		changed = true
		if v.State == "Deleting" {
			return tx.DeleteEventSourceMapping(key)
		}
		switch v.State {
		case "Creating", "Enabling", "Updating":
			v.State = "Enabled"
		case "Disabling":
			v.State = "Disabled"
		}
		if v.TransitionState != "" {
			v.State = v.TransitionState
			v.TransitionState = ""
		}
		v.Version++
		v.TransitionAt = time.Time{}
		// Native lifecycle settlement preserves the control operation's LastModified.
		return tx.PutEventSourceMapping(v)
	})
	if err == nil && changed {
		j.s.eventSourceMappingsChanged()
	}
	return err
}
