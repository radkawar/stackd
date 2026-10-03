package stepfunctions

import (
	"context"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// StartExecution admits service-owned executions through the same authorization,
// transaction, effects and audit boundary used by the generated frontend.
func (s *Service) StartExecution(ctx context.Context, in *api.StartExecutionInput) (*api.StartExecutionOutput, *awswire.Error) {
	model, _ := awscatalog.LookupService("stepfunctions")
	operation, _ := model.Operation("StartExecution")
	out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: in})
	if rejected != nil {
		return nil, rejected
	}
	return out.(*api.StartExecutionOutput), nil
}
