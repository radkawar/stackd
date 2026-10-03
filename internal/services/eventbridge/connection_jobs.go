package eventbridge

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type connectionJobs struct{ s *Service }

func (j connectionJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var v ConnectionRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; v, found, err = r.NextConnectionJob(); return err })
	return scheduler.Job{Key: v.ID, Version: v.Version, Due: v.Due}, found, err
}
func (j connectionJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var v ConnectionRecord
	selected := false
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = r.ConnectionByID(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		selected = v.Version == job.Version && !v.Due.IsZero() && !v.Due.After(s.clock.Now())
		return nil
	})
	if err != nil || !selected {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.Account, Region: v.Key.Region, ServicePrincipal: awsctx.ServicePrincipal{Name: "apidestinations.events.amazonaws.com", SourceARN: v.ARN(), Type: "AWSService"}})
	if v.State == "AUTHORIZING" {
		var c connectionSecret
		var token connectionToken
		var rejected *awswire.Error
		if s.connectionSecrets == nil {
			rejected = connectionResourceError("InternalError", "The connection secret store is unavailable.")
		} else {
			var body string
			body, rejected = s.connectionSecrets.ReadOwned(ctx, v.ARN(), v.SecretARN)
			if rejected == nil {
				c, rejected = decodeConnectionSecret(body)
			}
			if rejected == nil {
				token, rejected = s.acquireConnectionToken(ctx, c)
			} else {
				rejected = connectionResourceError("InternalError", "Unable to retrieve the connection credentials.")
			}
		}
		_, _, err = s.finishConnectionAuthorization(ctx, v, token, rejected)
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Connection(v.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != v.ID || current.Version != v.Version {
			return nil
		}
		switch current.State {
		case "DELETING":
			return tx.DeleteConnection(current.Key)
		case "DEAUTHORIZING":
			current.State = "DEAUTHORIZED"
		}
		current.Due = time.Time{}
		current.Version++
		if err := s.updateConnectionAPIDestinations(tx, v, current); err != nil {
			return err
		}
		return tx.PutConnection(current)
	})
}
