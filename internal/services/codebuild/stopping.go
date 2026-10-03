package codebuild

import (
	"context"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awswire"
	"time"
)

// StopBuild first commits cancellation intent, then waits outside every storage
// transaction for native termination. A disconnected caller cannot undo the stop.
func (s *Service) executeStopBuild(ctx context.Context) (any, *awswire.Error) {
	in, ok := awsapi.Input[api.StopBuildInput](ctx)
	if !ok {
		return nil, failure("InvalidInputException", "Missing StopBuild request.")
	}
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var build *BuildRecord
	err = s.repository.Attempt(ctx, func(tx Transaction) error { var err error; build, err = s.stopBuild(tx.Context(), tx, in); return err })
	if err != nil {
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err = s.recordCall(completion, "StopBuild", in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	s.controller.wake()
	key := build.Key
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !complete(*build) {
		select {
		case <-ctx.Done():
			return nil, wireError(ctx.Err())
		case <-ticker.C:
		}
		err = s.repository.View(ctx, func(r Reader) error {
			record, err := r.Build(key)
			if err == nil {
				build = &record
			}
			return err
		})
		if err != nil {
			return nil, wireError(err)
		}
	}
	if err = s.repository.Update(ctx, func(tx Transaction) error { return s.recordCall(tx.Context(), "StopBuild", in, build, nil) }); err != nil {
		return nil, wireError(err)
	}
	return &api.StopBuildOutput{Build: &build.Data}, nil
}
