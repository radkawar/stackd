package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"stackd/internal/scheduler"
	"stackd/internal/services/organizations"
	"stackd/mail"
)

type primaryEmailJobs struct{ service *Service }

func (source primaryEmailJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	s := source.service
	err := s.repository.View(ctx, func(reader Reader) error {
		records, err := reader.PrimaryEmailUpdates()
		if err != nil {
			return err
		}
		now := s.clock.Now()
		for _, record := range records {
			if record.Status != PrimaryEmailAccepted && !(record.Status == PrimaryEmailPending && record.NoticePending && now.Before(record.ExpiresAt) && s.emailSender != nil) {
				continue
			}
			job := scheduler.Job{Key: record.Scope.Partition + "\x00" + record.Scope.AccountID, Version: record.Generation, Due: record.Due}
			if !found || scheduler.Compare(job, next) < 0 {
				next, found = job, true
			}
		}
		return nil
	})
	return next, found, err
}

func (source primaryEmailJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := source.service
	partition, accountID, _ := strings.Cut(job.Key, "\x00")
	scope := Scope{partition, accountID}
	var selected PrimaryEmailUpdate
	err := s.repository.View(ctx, func(reader Reader) error {
		record, found, err := reader.PrimaryEmailUpdate(scope)
		if err == nil && found && record.Generation == job.Version && !record.Due.After(s.clock.Now()) {
			selected = record
		}
		return err
	})
	if err != nil {
		return err
	}
	if selected.Status == PrimaryEmailAccepted {
		return source.complete(ctx, scope, job.Version)
	}
	if selected.Status != PrimaryEmailPending || !selected.NoticePending || !s.clock.Now().Before(selected.ExpiresAt) || s.emailSender == nil {
		return nil
	}
	// No transaction spans SMTP delivery. A repeated delivery carries the same
	// code; publication below cannot overwrite a replacement or acceptance.
	err = s.emailSender.Send(ctx, mail.Message{To: selected.Email, Subject: "Verify your AWS account primary email", Text: fmt.Sprintf("Your verification code is %s.\nIt expires 24 hours after the update was requested.", selected.OTP)})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		slog.Warn("Account verification email delivery failed", "partition", scope.Partition, "account", scope.AccountID, "error", err)
	}
	deliveryErr := err
	return s.repository.Update(ctx, func(writer Writer) error {
		record, found, err := writer.PrimaryEmailUpdate(scope)
		if err != nil || !found || record.Generation != job.Version || record.Status != PrimaryEmailPending || !record.NoticePending {
			return err
		}
		if deliveryErr == nil {
			record.NoticePending = false
		} else {
			record.Due = s.clock.Now().UTC().Add(time.Second)
		}
		return writer.PutPrimaryEmailUpdate(record)
	})
}

func (source primaryEmailJobs) complete(ctx context.Context, scope Scope, generation uint64) error {
	s := source.service
	return s.repository.Update(ctx, func(writer Writer) error {
		record, found, err := writer.PrimaryEmailUpdate(scope)
		if err != nil || !found || record.Generation != generation || record.Status != PrimaryEmailAccepted || record.Due.After(s.clock.Now()) {
			return err
		}
		// TODO: Comeback verify accepted email-update behavior after competing account creation, membership/state changes and interrupted delivery; capture AWS failure and propagation semantics.
		err = s.organizations.PutPrimaryEmail(writer.Context(), scope.Partition, scope.AccountID, record.Email)
		if errors.Is(err, organizations.ErrPrimaryEmailInUse) {
			record.Status = PrimaryEmailFailed
		} else if err != nil {
			return err
		} else {
			record.Status = PrimaryEmailCompleted
		}
		record.UpdatedAt = s.clock.Now().UTC()
		return writer.PutPrimaryEmailUpdate(record)
	})
}
