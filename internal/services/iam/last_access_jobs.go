package iam

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

// AWS report jobs are asynchronous. This is a deterministic local processing
// interval, not a claim about AWS's completion or telemetry publication time.
const accessReportInterval = time.Second

type accessReportJobs struct{ service *Service }

func (source accessReportJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := source.service.repository.View(ctx, func(tx ReadTx) error {
		scopes, err := tx.AccessReportScopes()
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			reports, err := tx.PendingAccessReports(scope)
			if err != nil {
				return err
			}
			for _, report := range reports {
				job := scheduler.Job{Key: scope.Partition + "\x00" + scope.AccountID + "\x00" + report.ID, Due: report.RequestedAt.Add(accessReportInterval)}
				if !found || scheduler.Compare(job, next) < 0 {
					next, found = job, true
				}
			}
		}
		return nil
	})
	return next, found, err
}

func (source accessReportJobs) Run(ctx context.Context, job scheduler.Job) error {
	parts := strings.Split(job.Key, "\x00")
	if len(parts) != 3 {
		return errors.New("invalid access report job scope")
	}
	s := source.service
	scope := Scope{Partition: parts[0], AccountID: parts[1]}
	return s.repository.Update(ctx, func(tx WriteTx) error {
		report, err := tx.AccessReport(scope, parts[2])
		if errors.Is(err, ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		if report.CompletedAt != nil || report.RequestedAt.Add(accessReportInterval).After(now) {
			return nil
		}
		report.CompletedAt = &now
		return tx.PutAccessReport(scope, report)
	})
}
