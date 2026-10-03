package s3

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error {
	s.jobs.Close()
	return nil
}

type notificationChanges struct{ service *Service }

func (source notificationChanges) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := source.service.repository.View(ctx, func(r Reader) error {
		var err error
		job, found, err = r.NextNotificationChange()
		return err
	})
	return job, found, err
}

func (source notificationChanges) Run(ctx context.Context, job scheduler.Job) error {
	partition, bucket, _ := strings.Cut(job.Key, ":")
	return source.service.repository.Update(ctx, func(tx Transaction) error {
		state, err := tx.NotificationState(BucketKey{Partition: partition, Name: bucket})
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if state.Version != job.Version || state.ApplyAt == nil || state.ApplyAt.After(source.service.clock.Now()) {
			return nil
		}
		state.Applied = state.Desired
		state.ApplyAt = nil
		state.Version++
		return tx.PutNotificationState(state)
	})
}

type notificationDeliveries struct{ service *Service }

func (source notificationDeliveries) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := source.service.repository.View(ctx, func(r Reader) error {
		var err error
		job, found, err = r.NextNotificationDelivery()
		return err
	})
	return job, found, err
}

func (source notificationDeliveries) Run(ctx context.Context, job scheduler.Job) error {
	s := source.service
	var delivery NotificationDelivery
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		delivery, err = r.NotificationDelivery(job.Key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if delivery.Version != job.Version || delivery.Due.After(s.clock.Now()) {
		return nil
	}
	wire := unsupported("Notification destination commands are not configured.")
	if s.notifications != nil {
		wire = s.notifications.Send(ctx, delivery)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.NotificationDelivery(delivery.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != delivery.Version {
			return nil
		}
		if wire == nil || (wire.StatusCode < 500 && wire.StatusCode != 429) {
			return tx.DeleteNotificationDelivery(current.ID)
		}
		// TODO: Comeback establish S3's transient-producer retry cadence and
		// terminal budget; this local backoff is not SNS subscriber redelivery.
		current.Attempts++
		current.Due = s.clock.Now().Add(time.Second << min(current.Attempts, 8))
		current.Version++
		return tx.PutNotificationDelivery(current)
	})
}
