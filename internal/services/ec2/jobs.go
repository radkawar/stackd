package ec2

import (
	"context"
	"time"

	"stackd/internal/scheduler"
)

type computeJobs struct{ service *Service }

func (j computeJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	next, found, err := j.service.NextInstanceDeadline(ctx)
	if err != nil {
		return scheduler.Job{}, false, err
	}
	image, imageFound, err := j.service.NextImageDeadline(ctx)
	if err != nil {
		return scheduler.Job{}, false, err
	}
	if imageFound && (!found || image.Before(next)) {
		next, found = image, true
	}
	var association time.Time
	var associationFound bool
	err = j.service.repository.View(ctx, func(tx Reader) error {
		var err error
		association, associationFound, err = tx.NextInstanceProfileAssociationDeadline()
		return err
	})
	if err != nil {
		return scheduler.Job{}, false, err
	}
	if associationFound && (!found || association.Before(next)) {
		next, found = association, true
	}
	return scheduler.Job{Key: "ec2-compute", Due: next}, found, nil
}

func (j computeJobs) Run(ctx context.Context, _ scheduler.Job) error {
	if _, err := j.service.AdvanceInstanceProfileAssociations(ctx); err != nil {
		return err
	}
	if _, err := j.service.AdvanceImages(ctx); err != nil {
		return err
	}
	_, err := j.service.AdvanceInstances(ctx)
	return err
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

func (s *Service) Close() error {
	s.jobs.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.CloseInstanceControllers(ctx)
}
