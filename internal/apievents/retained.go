package apievents

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/journal"
)

type retainedOutcomesKey struct{}

// RetainedOutcomes holds completed, sanitized child API outcomes, never command
// inputs or resource mutations. It is confined to one synchronous command.
// Normal success leaves its records in the native transaction; Record is only
// for the owner after that command's savepoint has rolled back.
type RetainedOutcomes struct {
	parent *RetainedOutcomes
	calls  []retainedOutcome
}

type retainedOutcome struct {
	recorder Recorder
	metadata awsctx.Metadata
	envelope journal.Envelope
	call     journal.APICallCompleted
}

func RetainOutcomes(ctx context.Context) (context.Context, *RetainedOutcomes) {
	outcomes := &RetainedOutcomes{}
	return context.WithValue(ctx, retainedOutcomesKey{}, outcomes), outcomes
}

// RetainChildOutcomes isolates an opted-in child's savepoint. A failed child
// drops this scope and records its rejection in its original context instead.
func RetainChildOutcomes(ctx context.Context) (context.Context, *RetainedOutcomes) {
	parent, _ := ctx.Value(retainedOutcomesKey{}).(*RetainedOutcomes)
	if parent == nil {
		return ctx, nil
	}
	outcomes := &RetainedOutcomes{parent: parent}
	return context.WithValue(ctx, retainedOutcomesKey{}, outcomes), outcomes
}

// Accept retains only outcomes from a successfully completed child savepoint.
func (o *RetainedOutcomes) Accept() {
	if o != nil {
		o.parent.calls = append(o.parent.calls, o.calls...)
	}
}

// Record uses the owner's original context, preserving any enclosing caller
// transaction. An explicit rollback by that caller still removes these events.
func (o *RetainedOutcomes) Record(ctx context.Context) error {
	for _, outcome := range o.calls {
		if err := outcome.recorder.Record(awsctx.WithMetadata(ctx, outcome.metadata), outcome.envelope, outcome.call); err != nil {
			return err
		}
	}
	return nil
}

// RecordRetained opts a producer's final audit projection into its parent's
// rollback retention. No projection or service operation is executed again.
func RecordRetained(ctx context.Context, recorder Recorder, envelope journal.Envelope, call journal.APICallCompleted) error {
	outcomes, _ := ctx.Value(retainedOutcomesKey{}).(*RetainedOutcomes)
	if outcomes == nil {
		return recorder.Record(ctx, envelope, call)
	}
	if call.EventID == "" {
		var err error
		call.EventID, err = newEventID()
		if err != nil {
			return err
		}
	}
	if err := recorder.Record(ctx, envelope, call); err != nil {
		return err
	}
	outcomes.calls = append(outcomes.calls, retainedOutcome{recorder, awsctx.FromContext(ctx), envelope, call})
	return nil
}
