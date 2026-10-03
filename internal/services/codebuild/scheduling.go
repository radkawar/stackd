package codebuild

import (
	"context"
	"errors"
	runtime "stackd/compute/codebuild"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/scheduler"
	"strings"
)

type deadlineJobs struct{ s *Service }

func (j deadlineJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error {
		rows, e := r.ActiveBuilds()
		if e != nil {
			return e
		}
		for _, b := range rows {
			if complete(b) || b.StopRequested {
				continue
			}
			due := b.Deadline
			if due.IsZero() {
				due = b.QueuedDeadline
			}
			if due.IsZero() {
				continue
			}
			key := b.Key.Partition + "/" + b.Key.AccountID + "/" + b.Key.Region + "/" + b.Key.ID
			if !found || due.Before(job.Due) || due.Equal(job.Due) && key < job.Key {
				found = true
				job = scheduler.Job{Key: key, Due: due}
			}
		}
		return nil
	})
	return
}
func (j deadlineJobs) Run(ctx context.Context, job scheduler.Job) error {
	parts := strings.SplitN(job.Key, "/", 4)
	if len(parts) != 4 {
		return errors.New("invalid CodeBuild deadline key")
	}
	key := BuildKey{Scope: Scope{parts[0], parts[1], parts[2]}, ID: parts[3]}
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		r, err := tx.Build(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if complete(r) || r.StopRequested {
			return nil
		}
		due := r.Deadline
		if due.IsZero() {
			due = r.QueuedDeadline
		}
		if due.IsZero() || due.After(j.s.clock.Now()) {
			return nil
		}
		r.StopRequested = true
		r.Failure = "BUILD_TIMED_OUT"
		return tx.PutBuild(r)
	})
	if err == nil {
		j.s.controller.wake()
	}
	return err
}
func (c *controller) reconcileFleets() error {
	executor, ok := c.s.executor.(runtime.FleetExecutor)
	if !ok {
		return nil
	}
	var rows []FleetRecord
	var builds []BuildRecord
	err := c.s.repository.View(c.ctx, func(r Reader) error {
		var err error
		rows, err = r.AllFleets()
		if err != nil {
			return err
		}
		builds, err = r.ActiveBuilds()
		return err
	})
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Data.Status == nil {
			continue
		}
		state := value(r.Data.Status.StatusCode)
		if state == "DELETING" {
			// Admission precedes native source/image preparation and slot use.
			// DELETING excludes new claims, so this retained snapshot covers every
			// admitted build of the exact incarnation without a second lease store.
			draining := false
			for _, build := range builds {
				if build.FleetARN == value(r.Data.Arn) && !build.Deadline.IsZero() && (!complete(build) || build.CleanupPending) {
					draining = true
					break
				}
			}
			if draining {
				continue
			}
			err = executor.ReleaseFleet(c.ctx, value(r.Data.Arn))
			if errors.Is(err, runtime.ErrFleetBusy) {
				continue
			}
			if err != nil {
				return err
			}
			if err = c.s.repository.Update(c.ctx, func(tx Transaction) error {
				latest, err := tx.Fleet(r.Key)
				if err != nil {
					return err
				}
				if value(latest.Data.Arn) != value(r.Data.Arn) || value(latest.Data.Status.StatusCode) != "DELETING" {
					return nil
				}
				return tx.DeleteFleet(r.Key)
			}); err != nil {
				return err
			}
			continue
		}
		status, observedErr := executor.ReserveFleet(c.ctx, runtime.FleetSpecification{ARN: value(r.Data.Arn), Image: c.s.fleetImage, EnvironmentType: value(r.Data.EnvironmentType), ComputeType: value(r.Data.ComputeType), Capacity: int32(*r.Data.BaseCapacity)})
		next, message := "CREATING", ""
		if observedErr != nil {
			next = "CREATE_FAILED"
			message = observedErr.Error()
		} else if status.State == "ACTIVE" {
			next = "ACTIVE"
		}
		if next == state && message == value(r.Data.Status.Message) {
			continue
		}
		if err = c.s.repository.Update(c.ctx, func(tx Transaction) error {
			latest, err := tx.Fleet(r.Key)
			if err != nil {
				return err
			}
			if value(latest.Data.Arn) != value(r.Data.Arn) || value(latest.Data.Status.StatusCode) == "DELETING" {
				return nil
			}
			latest.Data.Status = &api.FleetStatus{StatusCode: new(api.FleetStatusCode(next))}
			if message != "" {
				latest.Data.Status.Message = new(api.String(message))
			}
			now := c.s.clock.Now()
			latest.Data.LastModified = &now
			return tx.PutFleet(latest)
		}); err != nil {
			return err
		}
	}
	return nil
}
