package iam

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type credentialReportJobs struct{ service *Service }

func (source credentialReportJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := source.service.repository.View(ctx, func(tx ReadTx) error {
		scopes, err := tx.CredentialReportScopes()
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			report, err := tx.CredentialReport(scope)
			if err != nil {
				return err
			}
			if report.State != CredentialReportPending {
				continue
			}
			job := scheduler.Job{Key: scope.Partition + "\x00" + scope.AccountID, Version: report.Generation, Due: report.RequestedAt}
			if !found || scheduler.Compare(job, next) < 0 {
				next, found = job, true
			}
		}
		return nil
	})
	return next, found, err
}

func (source credentialReportJobs) Run(ctx context.Context, job scheduler.Job) error {
	partition, accountID, ok := strings.Cut(job.Key, "\x00")
	if !ok || partition == "" || accountID == "" {
		return errors.New("invalid credential report job scope")
	}
	s := source.service
	scope := Scope{Partition: partition, AccountID: accountID}
	m := awsctx.Metadata{Partition: partition, AccountID: accountID}
	ctx = awsctx.WithMetadata(ctx, m)
	return s.repository.Update(ctx, func(tx WriteTx) error {
		now := s.clock.Now().UTC()
		report, err := tx.CredentialReport(scope)
		if errors.Is(err, ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if report.State != CredentialReportPending || report.Generation != job.Version || report.RequestedAt.After(now) {
			return nil
		}
		a, err := loadAccount(tx, scope)
		if err != nil {
			return err
		}
		if a.metadata == nil {
			// Invalid imported state must not leave an unfinishable pending
			// job ahead of every other account's work. A later Generate can
			// retry after provisioning metadata in its request transaction.
			report.State = CredentialReportFailed
			return tx.PutCredentialReport(scope, report)
		}
		a.currentTime = now
		borrowed := context.WithValue(ctx, transactionKey{}, serviceTransaction{service: s, tx: tx, currentTime: now})
		content, apiErr := s.credentialReportCSV(borrowed, a, m, a.metadata.CreatedAt)
		if err := ctx.Err(); err != nil {
			return err
		}
		if apiErr != nil {
			report.State = CredentialReportFailed
		} else {
			report.State = CredentialReportComplete
			report.GeneratedAt = now
			report.Content = content
		}
		return tx.PutCredentialReport(scope, report)
	})
}
