package apievents

import (
	"context"
	"slices"

	"stackd/journal"
)

// OutcomeGroup owns synchronous durability for independent read-only outcomes.
// Do must preserve ctx values and cancellation inside the callback, isolate its
// failures, and acknowledge success only after commit. If ctx already borrows a
// source transaction, Do must execute inline in that transaction instead.
// The composition root owns shutdown; a recorder does not close shared storage.
type OutcomeGroup interface {
	Do(context.Context, func(context.Context) error) error
}

// NewGrouped groups the complete sink callback for read-only outcomes only.
// Mutations retain New's inline behavior. A nil group also executes inline; a nil
// sink disables recording. Construct one group per active stack and drain it
// after stopping producers, before closing its underlying repositories.
func NewGrouped(sink Sink, group OutcomeGroup) Recorder {
	if sink == nil {
		return nil
	}
	return recorder{sink: sink, group: group}
}

func snapshotCall(call journal.APICallCompleted) journal.APICallCompleted {
	call.RequestParameters = slices.Clone(call.RequestParameters)
	call.ResponseElements = slices.Clone(call.ResponseElements)
	call.Resources = slices.Clone(call.Resources)
	call.EventResources = slices.Clone(call.EventResources)
	call.AdditionalEventData = slices.Clone(call.AdditionalEventData)
	call.ServiceEventDetails = slices.Clone(call.ServiceEventDetails)
	return call
}
