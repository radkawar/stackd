package ec2

import (
	"context"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awswire"
)

type externalSuccessKey struct{}
type externalSuccess func(context.Context, any) error

// RecordExternalSuccess records an admitted command in its resource transaction.
// The command calls it before committing admission, then performs native effects
// outside the transaction. Subsequent asynchronous failure belongs to admitted
// resource state: it must not replace that accepted API response with an error.
// Calls made directly between owners, without an external EC2 API command, do
// not acquire a second synthetic API audit event.
func RecordExternalSuccess(ctx context.Context, out any) error {
	record, ok := ctx.Value(externalSuccessKey{}).(externalSuccess)
	if !ok {
		return nil
	}
	return record(ctx, out)
}

// registerExternalOwnedCommand leaves transaction ownership with a command that
// performs real external effects. Successful admission must call
// RecordExternalSuccess inside its state transaction. Rejected admission is
// recorded here after rollback, including retained real cross-service outcomes.
func registerExternalOwnedCommand[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, &awswire.Error{Code: "InternalError", Message: "Missing generated EC2 request binding.", StatusCode: 500}
		}
		if s.recorder != nil {
			ctx = WithSnapshotAudit(ctx)
			var err error
			ctx, err = apievents.Reserve(ctx)
			if err != nil {
				return nil, wireError(err)
			}
		}
		ctx, outcomes := apievents.RetainOutcomes(ctx)
		ctx = context.WithValue(ctx, externalSuccessKey{}, externalSuccess(func(tx context.Context, out any) error {
			return s.recordCall(tx, action, in, out, nil)
		}))
		out, err := fn(ctx, in)
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.repository.Update(completion, func(tx Transaction) error {
			if err := outcomes.Record(tx.Context()); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, nil, rejected)
		}); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
