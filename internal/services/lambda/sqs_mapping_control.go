package lambda

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

type sqsMappingControl struct{ s *Service }

func (c sqsMappingControl) createSettings(in *api.CreateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	return sqsMappingCreateSettings(in)
}
func (c sqsMappingControl) updateSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	return applySQSMappingSettings(v, in, false)
}
func (c sqsMappingControl) preflight(ctx context.Context, f FunctionRecord, _ EventSourceMappingKey, source string, settings EventSourceMappingSettings, update *api.UpdateEventSourceMappingInput) *awswire.Error {
	if c.s.sqs == nil {
		return unsupported("SQS event source mappings require an SQS source adapter.")
	}
	consumer, wire := c.s.sqs.Open(ctx, f.Key, f.Role, source)
	if wire != nil {
		return wire
	}
	info, wire := consumer.Check(ctx)
	if wire != nil {
		if wire.StatusCode >= 500 {
			return failure("ServiceException", wire.Message, wire.StatusCode)
		}
		return mappingParameter(wire.Message)
	}
	if (update == nil || update.FunctionName != nil) && f.Timeout > info.VisibilitySeconds {
		return mappingParameter(fmt.Sprintf("Queue visibility timeout: %d seconds is less than Function timeout: %d seconds", info.VisibilitySeconds, f.Timeout))
	}
	return validateSQSMappingBatch(settings, info.FIFO)
}
func (c sqsMappingControl) createTransition(v *EventSourceMappingRecord, enabled bool) {
	v.State, v.StateTransitionReason = "Disabled", "USER_INITIATED"
	if enabled {
		v.State, v.TransitionAt = "Creating", v.LastModified.Add(eventSourceMappingTransitionDelay)
	}
}
func (c sqsMappingControl) updateTransition(v *EventSourceMappingRecord, enabled *api.Enabled) {
	v.StateTransitionReason = "USER_INITIATED"
	if enabled != nil && bool(*enabled) != (v.State == "Enabled") {
		if bool(*enabled) {
			v.State = "Enabling"
		} else {
			v.State = "Disabling"
		}
	} else if v.State == "Enabled" {
		v.State = "Updating"
	}
	if v.State != "Disabled" {
		v.TransitionAt = v.LastModified.Add(eventSourceMappingTransitionDelay)
	}
}
