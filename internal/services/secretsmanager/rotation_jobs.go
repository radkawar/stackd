package secretsmanager

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type rotationJobs struct{ s *Service }

type rotationSelection struct {
	job    scheduler.Job
	work   *RotationRecord
	secret *SecretRecord
}

func rotationWorkJob(work RotationRecord) scheduler.Job {
	return scheduler.Job{
		Key:     "rotation:callback:" + work.ARN + ":" + work.InvocationToken + ":" + strconv.Itoa(work.Step) + ":" + strconv.Itoa(work.Attempt),
		Version: uint64(work.Due.UnixNano()), Due: work.Due,
	}
}

func nextRotationJob(r Reader) (rotationSelection, bool, error) {
	var selected rotationSelection
	work, err := r.NextRotationWork()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return selected, false, err
	}
	found := err == nil
	if found {
		selected = rotationSelection{job: rotationWorkJob(work), work: &work}
	}
	secret, err := r.NextScheduledRotation()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return selected, false, err
	}
	if err == nil {
		job := scheduler.Job{Key: "rotation:schedule:" + secret.ARN, Version: uint64(secret.RotationDue.UnixNano()), Due: *secret.RotationDue}
		if !found || scheduler.Compare(job, selected.job) < 0 {
			selected = rotationSelection{job: job, secret: &secret}
			found = true
		}
	}
	return selected, found, nil
}

func (j rotationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var selected rotationSelection
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		selected, found, err = nextRotationJob(r)
		return err
	})
	return selected.job, found, err
}

func rotationRetryDelay(attempt int) time.Duration {
	// Backoff is a local delivery policy, not an asserted native retry cadence.
	return time.Second * time.Duration(1<<min(max(attempt-1, 0), 9))
}

func (j rotationJobs) Run(ctx context.Context, selected scheduler.Job) error {
	var invoke *RotationRecord
	var lambdaARN string
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		candidate, found, err := nextRotationJob(tx)
		if err != nil || !found || candidate.job != selected {
			return err
		}
		now := j.s.clock.Now().UTC()
		if selected.Due.After(now) {
			return nil
		}
		if candidate.secret != nil {
			return j.startScheduled(tx, *candidate.secret, now)
		}
		work := *candidate.work
		secret, err := tx.Secret(work.Secret)
		if errors.Is(err, ErrNotFound) {
			return tx.DeleteRotation(work.Secret)
		}
		if err != nil {
			return err
		}
		if secret.ARN != work.ARN || secret.Deleted != nil || secret.RotationEnabled == nil || !*secret.RotationEnabled {
			return tx.DeleteRotation(work.Secret)
		}
		if !now.Before(work.Deadline) {
			work.Due = work.Deadline
			if work.LastError == "" {
				work.LastError = "RotationWindowExpired: The rotation window closed before the callback completed."
			}
			return tx.PutRotation(work)
		}
		if work.Step < 0 || work.Step >= len(rotationSteps) {
			work.Due = work.Deadline
			work.LastError = "InvalidRotationStep: The retained callback stage is invalid."
			return tx.PutRotation(work)
		}
		version, err := tx.Version(VersionKey{Secret: secret.Key, ID: work.Token})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if errors.Is(err, ErrNotFound) || !slices.Contains(version.Stages, "AWSPENDING") && !(work.Step == 3 && slices.Contains(version.Stages, "AWSCURRENT")) {
			work.Due = work.Deadline
			work.LastError = "RotationVersionChanged: The rotation version no longer owns AWSPENDING."
			return tx.PutRotation(work)
		}
		// Claim this attempt before leaving the transaction. A crash replays
		// only this retained stage after its backoff, never a fabricated result.
		work.Attempt++
		work.Due = now.Add(rotationRetryDelay(work.Attempt))
		if work.Due.After(work.Deadline) {
			work.Due = work.Deadline
		}
		if err := tx.PutRotation(work); err != nil {
			return err
		}
		invoke, lambdaARN = &work, secret.RotationLambdaARN
		return nil
	})
	if err != nil || invoke == nil {
		return err
	}
	work := *invoke
	// The invocation adapter supplies actual Lambda execution-role identity to
	// customer API calls. This source principal only authorizes Invoke itself.
	// TODO: Comeback retain the originating API event ID for scheduled rotation callbacks.
	metadata := awsctx.Metadata{Partition: work.Secret.Partition, Region: work.Secret.Region, AccountID: work.Secret.AccountID}
	callCtx := awsctx.WithMetadata(ctx, metadata)
	principal := "secretsmanager.amazonaws.com"
	if work.Secret.Partition == "aws-cn" {
		principal = "secretsmanager.amazonaws.com.cn"
	}
	callCtx = awsctx.WithServicePrincipal(callCtx, awsctx.ServicePrincipal{Name: principal, SourceARN: work.ARN, Type: "AWSService"})
	var rejected *awswire.Error
	if j.s.rotation == nil {
		rejected = failure("InvalidRequestException", "Lambda rotation is not configured.")
	} else {
		rejected = j.s.rotation.Invoke(callCtx, lambdaARN, RotationEvent{SecretID: work.ARN, Token: work.Token, Step: rotationSteps[work.Step], RotationToken: work.InvocationToken})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Rotation(work.Secret)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		// Fence source incarnation, invocation token, stage, claim and window.
		// Cancellation or replacement while Lambda ran makes completion stale.
		if current != work {
			return nil
		}
		secret, err := tx.Secret(work.Secret)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if secret.ARN != work.ARN || secret.RotationLambdaARN != lambdaARN || secret.Deleted != nil || secret.RotationEnabled == nil || !*secret.RotationEnabled {
			return nil
		}
		now := j.s.clock.Now().UTC()
		if rejected != nil {
			return retainRotationFailure(tx, work, rejected, now)
		}
		version, err := tx.Version(VersionKey{Secret: secret.Key, ID: work.Token})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if errors.Is(err, ErrNotFound) {
			return retainRotationFailure(tx, work, failure("RotationVersionChanged", "The callback did not retain the rotation version."), now)
		}
		if work.TestOnly {
			// The successful test version becomes deprecated, not deleted. It
			// remains readable by VersionId with its encrypted value unchanged.
			removeStage(&version, "AWSPENDING")
			if err := tx.PutVersion(version); err != nil {
				return err
			}
			if err := tx.DeleteRotation(work.Secret); err != nil {
				return err
			}
			return j.s.refreshReplicas(tx, secret)
		}
		if work.Step == 0 {
			keys, err := tx.VersionKeyIDs(version.Key)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if len(keys) == 0 {
				return retainRotationFailure(tx, work, failure("RotationValueMissing", "createSecret completed without storing the pending secret value."), now)
			}
		}
		if work.Step == 3 {
			if !slices.Contains(version.Stages, "AWSCURRENT") {
				return retainRotationFailure(tx, work, failure("RotationNotFinished", "finishSecret completed without promoting the rotation version to AWSCURRENT."), now)
			}
			// finishSecret, not this worker, owns promotion and label changes.
			schedule, err := parseRotationSchedule(secret.RotationRules)
			if err != nil {
				return err
			}
			secret.LastRotated = &now
			if secret.RotationDue == nil {
				if err := setRotationSchedule(&secret, schedule, now, now); err != nil {
					return err
				}
			} else {
				due := *secret.RotationDue
				if !due.After(now) {
					due, _ = schedule.calendar.NextAfter(due, now)
				}
				if err := setRotationWindow(&secret, schedule, due, now); err != nil {
					return err
				}
			}
			if err := tx.PutSecret(secret); err != nil {
				return err
			}
			if err := tx.DeleteRotation(work.Secret); err != nil {
				return err
			}
			return j.s.refreshReplicas(tx, secret)
		}
		if !slices.Contains(version.Stages, "AWSPENDING") {
			return retainRotationFailure(tx, work, failure("RotationVersionChanged", "The pending staging label changed during the callback."), now)
		}
		work.Step++
		work.Attempt, work.LastError, work.Due = 0, "", now
		if !now.Before(work.Deadline) {
			work.Due = work.Deadline
			work.LastError = "RotationWindowExpired: The rotation window closed before the next callback."
		}
		return tx.PutRotation(work)
	})
}

func retainRotationFailure(tx Transaction, work RotationRecord, rejected *awswire.Error, now time.Time) error {
	work.LastError = rejected.Code + ": " + rejected.Message
	work.Due = now.Add(rotationRetryDelay(work.Attempt))
	if work.Due.After(work.Deadline) {
		work.Due = work.Deadline
	}
	return tx.PutRotation(work)
}

func (j rotationJobs) startScheduled(tx Transaction, secret SecretRecord, now time.Time) error {
	if secret.RotationEnabled == nil || !*secret.RotationEnabled || secret.Deleted != nil {
		secret.RotationDue = nil
		return tx.PutSecret(secret)
	}
	schedule, err := parseRotationSchedule(secret.RotationRules)
	if err != nil {
		return err
	}
	start := *secret.RotationDue
	deadline := schedule.end(start)
	next, ok := schedule.calendar.NextAfter(start, now)
	if !ok {
		return failure("InvalidParameterException", "The rotation schedule has no future occurrence.")
	}
	if err := setRotationWindow(&secret, schedule, next, now); err != nil {
		return err
	}
	if !now.Before(deadline) {
		// Do not execute a missed window outside its legal bounds, and do not
		// replay every missed occurrence after a restart or clock advance.
		if err := tx.PutSecret(secret); err != nil {
			return err
		}
		return j.s.refreshReplicas(tx, secret)
	}
	work, err := tx.Rotation(secret.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil && work.ARN == secret.ARN {
		if work.Due.Before(work.Deadline) {
			return tx.PutSecret(secret)
		}
		// A new legal window retries the known incomplete stage and token,
		// never invents promotion or loses the original failed callback.
		work.Due, work.Deadline, work.Attempt, work.InvocationToken = now, deadline, 0, identifier()
		if err := tx.PutRotation(work); err != nil {
			return err
		}
	} else {
		versions, err := tx.Versions(secret.Key)
		if err != nil {
			return err
		}
		for _, version := range versions {
			if slices.Contains(version.Stages, "AWSPENDING") && !slices.Contains(version.Stages, "AWSCURRENT") {
				// A manually retained pending version has no known callback stage.
				// Do not guess one or replace that version with a competing token.
				return tx.PutSecret(secret)
			}
		}
		if err := j.s.beginRotation(tx, &secret, versions, identifier(), false, now, deadline); err != nil {
			return err
		}
	}
	end := deadline.Add(-time.Second)
	secret.NextRotation, secret.Changed = &end, now
	if err := tx.PutSecret(secret); err != nil {
		return err
	}
	return j.s.refreshReplicas(tx, secret)
}
