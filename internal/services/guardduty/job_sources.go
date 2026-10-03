package guardduty

import (
	"context"
	"strings"

	"stackd/internal/scheduler"
)

type serviceJobs struct{ s *Service }

func (j serviceJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	next, found, err := findingJobs(j).Next(ctx)
	if err != nil {
		return next, found, err
	}
	list, listed, err := ipListJobs(j).Next(ctx)
	if err != nil {
		return list, listed, err
	}
	if listed && (!found || scheduler.Compare(list, next) < 0) {
		next, found = list, true
	}
	export, exported, err := destinationJobs(j).Next(ctx)
	if err != nil {
		return export, exported, err
	}
	if exported && (!found || scheduler.Compare(export, next) < 0) {
		return export, true, nil
	}
	return next, found, nil
}

func (j serviceJobs) Run(ctx context.Context, job scheduler.Job) error {
	if strings.Contains(job.Key, "/ipset/") || strings.Contains(job.Key, "/threatintelset/") {
		return ipListJobs(j).Run(ctx, job)
	}
	if strings.Contains(job.Key, "/publishingdestination/") {
		return destinationJobs(j).Run(ctx, job)
	}
	return findingJobs(j).Run(ctx, job)
}
