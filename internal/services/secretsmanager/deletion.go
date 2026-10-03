package secretsmanager

import (
	"context"
	"encoding/json"
	"errors"

	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/journal"
)

type deletionJobs struct{ s *Service }

func (j deletionJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var secret SecretRecord
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; secret, err = r.NextDeletion(); return err })
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: secret.ARN, Due: *secret.DeleteAfter}, true, nil
}
func (j deletionJobs) Run(ctx context.Context, job scheduler.Job) error {
	// TODO: Comeback retain the originating API event ID for scheduled secret deletion.
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		secret, err := tx.NextDeletion()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if secret.ARN != job.Key || !secret.DeleteAfter.Equal(job.Due) || secret.DeleteAfter.After(j.s.clock.Now()) {
			return nil
		}
		return j.s.removeSecret(tx, secret)
	})
}
func (s *Service) removeSecret(tx Transaction, secret SecretRecord) error {
	if err := s.recordServiceEvent(tx.Context(), "StartSecretVersionDelete", secret); err != nil {
		return err
	}
	if err := tx.DeleteSecret(secret.Key); err != nil {
		return err
	}
	return s.recordServiceEvent(tx.Context(), "EndSecretVersionDelete", secret)
}
func (s *Service) recordServiceEvent(ctx context.Context, name string, secret SecretRecord) error {
	if s.recorder == nil {
		return nil
	}
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = awsctx.FromContext(ctx).ParentEventID
	}
	metadata := awsctx.Metadata{Partition: secret.Key.Partition, AccountID: secret.Key.AccountID, Region: secret.Key.Region, ParentEventID: parent, ServicePrincipal: awsctx.ServicePrincipal{Name: "secretsmanager.amazonaws.com", SourceARN: secret.ARN, Type: "AWSService"}}
	ctx, err := apievents.Reserve(awsctx.WithMetadata(ctx, metadata))
	if err != nil {
		return err
	}
	additional, err := json.Marshal(struct {
		ARN  string `json:"ARN"`
		Name string `json:"Name"`
	}{secret.ARN, secret.Key.Name})
	if err != nil {
		return err
	}
	call := journal.APICallCompleted{EventID: apievents.EventID(ctx), EventSource: "secretsmanager.amazonaws.com", EventName: name, Category: journal.CategoryManagement, ServiceEvent: true, AdditionalEventData: additional}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: secret.Key.Partition, AccountID: secret.Key.AccountID, Region: secret.Key.Region}, call)
}
