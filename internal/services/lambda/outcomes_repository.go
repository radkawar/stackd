package lambda

import (
	"context"

	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// OutcomeTargets checks and sends through the destination's ordinary authorization
// and command boundary. Platform calls use the execution role without the
// lambda:SourceFunctionArn context attached to customer runtime credentials.
// Successful Send means destination acceptance, not completion of target code.
type OutcomeTargets interface {
	Check(ctx context.Context, function FunctionKey, roleARN, destinationARN string) *awswire.Error
	Send(context.Context, InvocationRecord, OutcomeDeliveryRecord) *awswire.Error
}

// OutcomeDeliveryRecord references one completed invocation, retaining its payload
// once even when an OnFailure destination and a legacy dead-letter queue coexist.
// Accepted routes are immutable. The scheduler retries an unacknowledged effect
// after restart; no delivery receipt or second transaction protocol is introduced.
type OutcomeDeliveryRecord struct {
	ID, InvocationID, DestinationARN string
	DeadLetter                       bool
}

type OutcomeReader interface {
	OutcomeDelivery(string) (OutcomeDeliveryRecord, error)
	NextOutcomeDelivery() (scheduler.Job, bool, error)
}

type OutcomeWriter interface {
	PutOutcomeDelivery(OutcomeDeliveryRecord) error
	// DeleteOutcomeDelivery also collects the completed invocation when its last
	// delivery has been acknowledged. Function deletion does not cancel this work.
	DeleteOutcomeDelivery(string) error
}
