package integrations

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
)

func (a EventBridgeTargets) sendCodePipeline(ctx context.Context, request eventbridge.DeliveryRequest, target arn.ARN, body string) *awswire.Error {
	if a.CodePipeline == nil {
		return &awswire.Error{Code: "InternalFailure", Message: "CodePipeline target delivery is not configured.", StatusCode: 500}
	}
	var input api.StartPipelineExecutionInput
	if err := json.Unmarshal([]byte(body), &input); err != nil {
		return &awswire.Error{Code: "INVALID_JSON", Message: "CodePipeline target input is not a valid execution request: " + err.Error(), StatusCode: 400}
	}
	// The target ARN owns routing; an input transform cannot redirect delivery.
	input.Name = new(api.PipelineName(target.Resource))
	if input.ClientRequestToken == nil {
		input.ClientRequestToken = new(api.ClientRequestToken(request.Delivery.ID))
	}
	metadata := awsctx.FromContext(ctx)
	// Keep the role identity. SourceARN records the actual trigger, not a grant
	// of service-principal authority or an extra public request parameter.
	metadata.ServicePrincipal.SourceARN = request.Delivery.RuleARN
	model, _ := awscatalog.LookupService("codepipeline")
	operation, _ := model.Operation("StartPipelineExecution")
	_, rejected := a.CodePipeline.ExecuteCommand(awsctx.WithMetadata(ctx, metadata), awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &input})
	return rejected
}
