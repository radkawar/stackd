package integrations

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/secretsmanager"
)

// SecretRotationLambda admits through Lambda's current resource policy and runs
// its real configured executor; a successful DryRun never starts customer code.
type SecretRotationLambda interface {
	CheckInvoke(context.Context, string) *awswire.Error
	Invoke(context.Context, *api.InvokeInput) (*api.InvokeOutput, string, *awswire.Error)
}

type SecretRotation struct{ Lambda SecretRotationLambda }

func rotationContext(ctx context.Context, functionARN, secretARN string) (context.Context, *awswire.Error) {
	function, err := arn.Parse(functionARN)
	if err != nil || function.Service != "lambda" {
		return nil, &awswire.Error{Code: "InvalidParameterException", Message: "Invalid rotation Lambda ARN.", StatusCode: 400}
	}
	secret, err := arn.Parse(secretARN)
	if err != nil {
		return nil, &awswire.Error{Code: "InvalidParameterException", Message: "Invalid rotation secret ARN.", StatusCode: 400}
	}
	metadata := awsctx.FromContext(ctx)
	metadata = awsctx.Metadata{Partition: secret.Partition, AccountID: secret.AccountID, Region: function.Region, ParentEventID: metadata.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: "secretsmanager.amazonaws.com", SourceARN: secretARN, Type: "AWSService"}}
	return awsctx.WithMetadata(ctx, metadata), nil
}

func (r SecretRotation) Validate(ctx context.Context, functionARN, secretARN string) *awswire.Error {
	ctx, rejected := rotationContext(ctx, functionARN, secretARN)
	if rejected != nil {
		return rejected
	}
	return r.Lambda.CheckInvoke(ctx, functionARN)
}

func (r SecretRotation) Invoke(ctx context.Context, functionARN string, event secretsmanager.RotationEvent) *awswire.Error {
	ctx, rejected := rotationContext(ctx, functionARN, event.SecretID)
	if rejected != nil {
		return rejected
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return &awswire.Error{Code: "InternalServiceError", Message: err.Error(), StatusCode: 500}
	}
	out, _, rejected := r.Lambda.Invoke(ctx, &api.InvokeInput{FunctionName: new(api.NamespacedFunctionName(functionARN)), InvocationType: new(api.InvocationType("RequestResponse")), Payload: payload})
	if rejected != nil {
		return rejected
	}
	if out.FunctionError != nil {
		return &awswire.Error{Code: "LambdaFunctionError", Message: string(out.Payload), StatusCode: 502}
	}
	return nil
}
