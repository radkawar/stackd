package cloudcontrol

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/cloudformation"
)

type requestJobs struct{ s *Service }

func (j requestJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var op RequestRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; op, found, err = r.NextRequest(); return err })
	return scheduler.Job{Key: op.Token, Version: op.Revision, Due: op.Due}, found, err
}
func (j requestJobs) Run(ctx context.Context, job scheduler.Job) error { return j.s.run(ctx, job) }
func (s *Service) run(ctx context.Context, job scheduler.Job) error {
	var op RequestRecord
	err := s.repository.View(ctx, func(r Reader) error { var err error; op, err = r.Request(job.Key); return err })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !active(op.Status) || op.Revision != job.Version {
		return nil
	}
	if op.Status == "CANCEL_IN_PROGRESS" {
		op.Status = "CANCEL_COMPLETE"
		op.Phase = "DONE"
		return s.complete(ctx, job, op)
	}
	credentialLifetime := 24 * time.Hour
	if op.RoleARN != "" {
		credentialLifetime = 36 * time.Hour
	}
	if !s.clock.Now().Before(op.Created.Add(credentialLifetime)) {
		op.Status = "FAILED"
		op.Phase = "DONE"
		op.ErrorCode = "InvalidCredentials"
		op.Message = "The credentials for this resource operation have expired."
		return s.complete(ctx, job, op)
	}
	caller := op.Caller
	caller.InvokedBy = "cloudformation.amazonaws.com"
	caller.SourceIP = caller.InvokedBy
	caller.UserAgent = caller.InvokedBy
	caller.TransportKnown = true
	caller.SecureTransport = true
	commandCtx := awsctx.WithViaService(awsctx.WithMetadata(ctx, caller), caller.InvokedBy)
	if op.RoleARN != "" {
		if s.roles == nil {
			err = failure("InvalidCredentialsException", "Cloud Control execution-role authority is unavailable.")
		} else {
			commandCtx, err = s.roles.Context(commandCtx, "", op.RoleARN)
		}
	}
	if err == nil {
		err = s.effect(commandCtx, &op)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		op.Status = "FAILED"
		op.Phase = "DONE"
		op.ErrorCode = handlerErrorCode(err)
		op.Message = err.Error()
	}
	return s.complete(ctx, job, op)
}
func (s *Service) complete(ctx context.Context, job scheduler.Job, op RequestRecord) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Request(job.Key)
		if err != nil {
			return err
		}
		if current.Revision != job.Version || !active(current.Status) {
			return nil
		}
		op.Revision++
		op.EventTime = s.clock.Now()
		op.Due = op.EventTime
		if active(op.Status) {
			op.Due = op.Due.Add(time.Second)
		}
		return tx.PutRequest(op)
	})
}
func (s *Service) effect(ctx context.Context, op *RequestRecord) error {
	h, reader, err := s.handler(op.TypeName, "")
	if err != nil {
		return err
	}
	r := resourceRequest(*op)
	if op.Operation == "DELETE" && op.Phase == "APPLY" {
		properties, err := reader.Read(ctx, r)
		if err != nil {
			return err
		}
		op.Before = encode(cloudformation.WritableResourceProperties(op.TypeName, properties))
		op.Desired = op.Before
		// Commit existence and the exact admitted identity before deletion.
		// A recovered delete may then observe absence without changing an
		// originally absent resource into a successful delete.
		op.Phase = "MUTATE"
		return nil
	}
	if op.Phase != "STABILIZE" {
		var result cloudformation.ResourceResult
		switch op.Operation {
		case "CREATE":
			result, err = h.Create(ctx, r)
		case "UPDATE":
			result, err = h.Update(ctx, r)
		case "DELETE":
			err = h.Delete(ctx, r)
			if err != nil && handlerErrorCode(err) == "NotFound" {
				err = nil
			}
		}
		if result.PhysicalID != "" {
			op.Identifier = result.PhysicalID
			r.PhysicalID = result.PhysicalID
		}
		if err != nil {
			return err
		}
		op.Phase = "STABILIZE"
	}
	var ready = true
	if op.Operation == "DELETE" {
		if stabilizer, ok := h.(cloudformation.ResourceDeletionStabilizer); ok {
			ready, err = stabilizer.StabilizeDeletion(ctx, r)
		}
	} else if stabilizer, ok := h.(cloudformation.ResourceStabilizer); ok {
		ready, err = stabilizer.Stabilize(ctx, r)
	}
	if err != nil || !ready {
		return err
	}
	if op.Operation != "DELETE" {
		model, err := reader.Read(ctx, r)
		if err != nil {
			return err
		}
		op.Model = encode(model)
		identifier, err := cloudformation.ResourceIdentifier(op.TypeName, model)
		if err != nil {
			return err
		}
		op.Identifier = identifier
	}
	op.Status = "SUCCESS"
	op.Phase = "DONE"
	return nil
}
func handlerErrorCode(err error) string {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		switch wire.Code {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return "AccessDenied"
		case "NoSuchEntity", "NoSuchBucket", "NotFound", "ResourceNotFound", "ResourceNotFoundException", "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue", "ParameterNotFound", "RepositoryNotFoundException":
			return "NotFound"
		case "AlreadyExists", "AlreadyExistsException", "ResourceAlreadyExistsException", "BucketAlreadyExists", "BucketAlreadyOwnedByYou", "QueueNameExists", "EntityAlreadyExists", "ParameterAlreadyExists", "RepositoryAlreadyExistsException":
			return "AlreadyExists"
		case "LimitExceededException", "ResourceLimitExceededException":
			return "ServiceLimitExceeded"
		case "ThrottlingException", "Throttling", "TooManyRequestsException":
			return "Throttling"
		// NotUpdatable is reserved for updates to create-only properties.
		case "UnsupportedActionException", "NotImplementedException", "InternalError", "InternalFailure", "GeneralServiceException":
			return "GeneralServiceException"
		case "InvalidCredentialsException":
			return "InvalidCredentials"
		}
	}
	return "InvalidRequest"
}
func readError(err error) error {
	code := handlerErrorCode(err)
	switch code {
	case "NotFound":
		return failure("ResourceNotFoundException", err.Error())
	case "AccessDenied":
		return failure("AccessDeniedException", err.Error())
	}
	if strings.HasSuffix(code, "Exception") {
		return failure(code, err.Error())
	}
	return failure("HandlerFailureException", err.Error())
}
