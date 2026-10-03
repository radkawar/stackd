package ecs

import (
	"context"
	"errors"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
)

// RunTask is the authorized ECS command used by both the generated frontend and
// service producers. Task intents and their API outcome commit together; native
// execution starts only after acceptance commits.
func (s *Service) RunTask(ctx context.Context, in *api.RunTaskInput) (*api.RunTaskOutput, *awswire.Error) {
	return runCommand(s, ctx, "RunTask", in, s.runTask, s.tasks.wake)
}

// DescribeServices applies the same current authorization and audit boundary to
// service integrations as to SDK callers.
func (s *Service) DescribeServices(ctx context.Context, in *api.DescribeServicesInput) (*api.DescribeServicesOutput, *awswire.Error) {
	return runCommand(s, ctx, "DescribeServices", in, s.describeServices)
}

// UpdateService changes retained service intent through the frontend's command.
// Native container reconciliation starts only after that command commits.
func (s *Service) UpdateService(ctx context.Context, in *api.UpdateServiceInput) (*api.UpdateServiceOutput, *awswire.Error) {
	return runCommand(s, ctx, "UpdateService", in, s.updateService, s.tasks.wake)
}

func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(context.Context, Transaction, *I) (*O, error), committed ...func()) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var out *O
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		out, err = fn(tx.Context(), tx, in)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, in, out, nil)
	})
	if err == nil {
		for _, notify := range committed {
			notify()
		}
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	var dependency interface{ RecordRejection(context.Context) error }
	if errors.As(err, &dependency) {
		if err := dependency.RecordRejection(completion); err != nil {
			return nil, wireError(err)
		}
	}
	if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
