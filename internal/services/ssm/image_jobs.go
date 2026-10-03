package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// Images validates against the existing regional EC2 owner with the admitted
// caller's live DescribeImages authority; Parameter Store mirrors no AMI catalog.
type Images interface {
	ValidateParameterImage(context.Context, string) error
}
type imageJobs struct{ s *Service }

func (j imageJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var first ValidationJob
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		first, err = r.NextValidationJob()
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: parameterARN(first.Key.Parameter) + ":" + strconv.FormatInt(first.Key.Version, 10), Due: first.Due}, true, nil
}
func (j imageJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		selected, err := tx.NextValidationJob()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if parameterARN(selected.Key.Parameter)+":"+strconv.FormatInt(selected.Key.Version, 10) != job.Key || !selected.Due.Equal(job.Due) || selected.Due.After(j.s.clock.Now()) {
			return nil
		}
		p, err := tx.Parameter(selected.Key.Parameter)
		if errors.Is(err, ErrNotFound) {
			return tx.DeleteValidationJob(selected.Key)
		}
		if err != nil {
			return err
		}
		v, err := tx.Version(selected.Key)
		if err != nil {
			return err
		}
		caller := selected.Caller
		caller.RequestID = identifier()
		validationCtx := awsctx.WithMetadata(tx.Context(), caller)
		// EC2 rejection is a terminal validation result, not a failure of the
		// enclosing parameter transition. Its savepoint must not poison the
		// transaction that removes pending work and publishes the failure event.
		validationErr := j.s.repository.Attempt(validationCtx, func(attempt Transaction) error {
			return j.s.images.ValidateParameterImage(attempt.Context(), string(v.Value))
		})
		operation := "Update"
		if p.CurrentVersion == 0 {
			operation = "Create"
		}
		if validationErr != nil {
			if err := j.s.emitImageFailure(tx, p, operation); err != nil {
				return err
			}
			if p.CurrentVersion == 0 {
				return j.s.removeParameter(tx, p)
			}
			if err := tx.DeleteValidationJob(v.Key); err != nil {
				return err
			}
			return tx.DeleteVersion(v.Key)
		}
		versions, err := tx.Versions(p.Key)
		if err != nil {
			return err
		}
		if len(versions) > 100 {
			slices.SortFunc(versions, func(a, b VersionRecord) int {
				if a.Key.Version < b.Key.Version {
					return -1
				}
				if a.Key.Version > b.Key.Version {
					return 1
				}
				return 0
			})
			if len(versions[0].Labels) > 0 {
				if err := j.s.emitImageFailure(tx, p, operation); err != nil {
					return err
				}
				if err := tx.DeleteValidationJob(v.Key); err != nil {
					return err
				}
				return tx.DeleteVersion(v.Key)
			}
			if err := tx.DeleteVersion(versions[0].Key); err != nil {
				return err
			}
		}
		promoteVersion(&p, v)
		if err := tx.PutParameter(p); err != nil {
			return err
		}
		if err := tx.DeleteValidationJob(v.Key); err != nil {
			return err
		}
		return j.s.emitChange(tx, p, operation)
	})
}
func (s *Service) emitImageFailure(tx Transaction, p ParameterRecord, operation string) error {
	if s.events == nil {
		return nil
	}
	detail, err := json.Marshal(struct {
		Exception string `json:"exception"`
		DataType  string `json:"dataType"`
		Name      string `json:"name"`
		Type      string `json:"type"`
		Operation string `json:"operation"`
	}{"Unable to Describe Resource", "aws:ec2:image", p.Key.Name, "String", operation})
	if err != nil {
		return err
	}
	return s.events.PublishEvent(tx.Context(), Event{Scope: p.Key.Scope, ID: identifier(), DetailType: "Parameter Store Change", Detail: detail, Resources: []string{p.ARN}, At: s.clock.Now()})
}
