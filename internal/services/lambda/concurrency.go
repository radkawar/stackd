package lambda

import (
	"context"
	"errors"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

const (
	lambdaConcurrentExecutions = 1000
	lambdaUnreservedMinimum    = 100
)

func (s *Service) registerConcurrency() {
	register(s, "GetFunctionConcurrency", s.getFunctionConcurrency)
	register(s, "PutFunctionConcurrency", s.putFunctionConcurrency)
	register(s, "DeleteFunctionConcurrency", s.deleteFunctionConcurrency)
	register(s, "GetAccountSettings", s.getAccountSettings)
}

func (s *Service) concurrencyFunction(r Reader, ref FunctionReference, action string) (FunctionRecord, error) {
	function, err := r.Function(ref.FunctionKey)
	if errors.Is(err, ErrNotFound) {
		// Missing resources still require permission on the requested ARN.
		if wire := s.authorize(r.Context(), action, ref.ARN(), nil, nil, nil); wire != nil {
			return FunctionRecord{}, wire
		}
		return FunctionRecord{}, err
	}
	if err != nil {
		return FunctionRecord{}, err
	}
	if wire := s.authorizeFunction(r, action, ref, function, nil); wire != nil {
		return FunctionRecord{}, wire
	}
	if ref.Qualifier != "" {
		return FunctionRecord{}, failure("InvalidParameterValueException", "Function concurrency requires an unqualified function name.", 400)
	}
	return function, nil
}

func (s *Service) getFunctionConcurrency(ctx context.Context, in *api.GetFunctionConcurrencyInput) (*api.GetFunctionConcurrencyOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	out := &api.GetFunctionConcurrencyOutput{}
	err := s.repository.View(ctx, func(r Reader) error {
		if _, err := s.concurrencyFunction(r, ref, "GetFunctionConcurrency"); err != nil {
			return err
		}
		reserved, present, err := r.FunctionConcurrency(ref.FunctionKey)
		if err != nil {
			return err
		}
		if present {
			out.ReservedConcurrentExecutions = new(api.ReservedConcurrentExecutions(reserved))
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) putFunctionConcurrency(ctx context.Context, in *api.PutFunctionConcurrencyInput) (*api.PutFunctionConcurrencyOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	key := ref.FunctionKey
	reserved := int32(*in.ReservedConcurrentExecutions)
	out := &api.PutFunctionConcurrencyOutput{ReservedConcurrentExecutions: new(api.ReservedConcurrentExecutions(reserved))}
	// Admission and reservation mutations share the service-to-repository order.
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := s.concurrencyFunction(tx, ref, "PutFunctionConcurrency")
		if err != nil {
			return err
		}
		if function.Capacity != nil {
			return failure("InvalidParameterValueException", "Lambda Managed Instances do not support reserved concurrency.", 400)
		}
		current, present, err := tx.FunctionConcurrency(key)
		if err != nil {
			return err
		}
		if !present || current != reserved {
			usage, err := tx.AccountUsage(key.Scope)
			if err != nil {
				return err
			}
			if usage.ReservedConcurrency-int64(current)+int64(reserved) > lambdaConcurrentExecutions-lambdaUnreservedMinimum {
				return failure("InvalidParameterValueException", "Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [100].", 400)
			}
			if err := tx.PutFunctionConcurrency(key, reserved); err != nil {
				return err
			}
			if err := validateProvisionedReservations(tx, key); err != nil {
				return err
			}
			if err := rotateConcurrencyRevision(tx, function); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), "PutFunctionConcurrency", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.reservationChanged(key, true)
	return out, nil
}

func (s *Service) deleteFunctionConcurrency(ctx context.Context, in *api.DeleteFunctionConcurrencyInput) (*api.DeleteFunctionConcurrencyOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	key := ref.FunctionKey
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := s.concurrencyFunction(tx, ref, "DeleteFunctionConcurrency")
		if err != nil {
			return err
		}
		_, present, err := tx.FunctionConcurrency(key)
		if err != nil {
			return err
		}
		if present {
			if err := tx.DeleteFunctionConcurrency(key); err != nil {
				return err
			}
			if err := validateProvisionedReservations(tx, key); err != nil {
				return err
			}
			if err := rotateConcurrencyRevision(tx, function); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), "DeleteFunctionConcurrency", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.reservationChanged(key, false)
	return &api.DeleteFunctionConcurrencyOutput{}, nil
}

func rotateConcurrencyRevision(tx Transaction, function FunctionRecord) error {
	function.Revision = uuid.NewString()
	if err := tx.PutFunction(function); err != nil {
		return err
	}
	pending, err := tx.PendingFunction(function.Key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	pending.Revision = function.Revision
	return tx.PutPendingFunction(pending)
}

func (s *Service) getAccountSettings(ctx context.Context, _ *api.GetAccountSettingsInput) (*api.GetAccountSettingsOutput, *awswire.Error) {
	var usage AccountUsage
	var provisioned int64
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorize(r.Context(), "GetAccountSettings", "*", nil, nil, nil); wire != nil {
			return wire
		}
		var err error
		usage, err = r.AccountUsage(scopeFor(ctx))
		if err != nil {
			return err
		}
		_, provisioned, err = committedProvisioned(r, scopeFor(ctx))
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.GetAccountSettingsOutput{
		AccountLimit: &api.AccountLimit{
			TotalCodeSize:                  new(api.Long(300 * 1024 * 1024 * 1024)),
			CodeSizeUnzipped:               new(api.Long(250 * 1024 * 1024)),
			CodeSizeZipped:                 new(api.Long(50 * 1024 * 1024)),
			ConcurrentExecutions:           new(api.Integer(lambdaConcurrentExecutions)),
			UnreservedConcurrentExecutions: new(api.UnreservedConcurrentExecutions(lambdaConcurrentExecutions - usage.ReservedConcurrency - provisioned)),
		},
		AccountUsage: &api.AccountUsage{
			FunctionCount: new(api.Long(usage.FunctionCount)),
			TotalCodeSize: new(api.Long(usage.TotalCodeSize)),
		},
	}, nil
}
