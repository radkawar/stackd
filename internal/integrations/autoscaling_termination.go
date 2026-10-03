package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/services/autoscaling"
)

// AutoScalingTerminationFunctions is Lambda's ordinary synchronous API. The
// supplied execution context is the current Auto Scaling service-linked role,
// not a service-principal permission bypass or the group's creating caller.
type AutoScalingTerminationFunctions interface {
	Invoke(context.Context, *api.InvokeInput) (*api.InvokeOutput, string, *awswire.Error)
}

type AutoScalingTermination struct {
	Functions AutoScalingTerminationFunctions
}

var _ autoscaling.TerminationSelector = AutoScalingTermination{}

func (a AutoScalingTermination) Validate(ctx context.Context, function string) error {
	if a.Functions == nil {
		return errors.New("autoscaling: Lambda execution is not configured")
	}
	_, _, rejected := a.Functions.Invoke(autoScalingCommandContext(ctx), &api.InvokeInput{
		FunctionName:   new(api.NamespacedFunctionName(function)),
		InvocationType: new(api.InvocationType("DryRun")),
	})
	if rejected != nil {
		return rejected
	}
	return nil
}

func (a AutoScalingTermination) Select(ctx context.Context, request autoscaling.TerminationPolicyRequest) ([]string, error) {
	if a.Functions == nil {
		return nil, errors.New("autoscaling: Lambda execution is not configured")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	output, _, rejected := a.Functions.Invoke(autoScalingCommandContext(ctx), &api.InvokeInput{
		FunctionName:   new(api.NamespacedFunctionName(request.FunctionARN)),
		InvocationType: new(api.InvocationType("RequestResponse")),
		Payload:        api.Blob(payload),
	})
	if rejected != nil {
		return nil, rejected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if output == nil {
		return nil, errors.New("autoscaling: Lambda returned no invocation result")
	}
	if output.FunctionError != nil && string(*output.FunctionError) != "" {
		return nil, fmt.Errorf("autoscaling: Lambda termination function failed: %s", *output.FunctionError)
	}
	var decision struct {
		InstanceIDs []string `json:"InstanceIDs"`
	}
	if err := json.Unmarshal(output.Payload, &decision); err != nil {
		return nil, fmt.Errorf("autoscaling: invalid Lambda termination response: %w", err)
	}
	return decision.InstanceIDs, nil
}
