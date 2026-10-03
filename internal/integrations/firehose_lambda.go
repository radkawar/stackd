package integrations

import (
	"context"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/services/firehose"
)

// FirehoseLambdaCommands leaves function authorization, admission and customer
// execution in Lambda. A function error is a successful Invoke with an error payload.
type FirehoseLambdaCommands interface {
	Invoke(context.Context, *api.InvokeInput) (*api.InvokeOutput, string, *awswire.Error)
}

type FirehoseLambda struct {
	Roles     ServiceRoles
	Functions FirehoseLambdaCommands
	sessions  serviceRoleSessions
}

func (a *FirehoseLambda) Invoke(ctx context.Context, stream firehose.StreamKey, functionARN, roleARN string, payload []byte) (*api.InvokeOutput, *awswire.Error) {
	ctx, err := a.sessions.context(ctx, a.Roles, firehosePrincipal(stream), roleARN, "Firehose", stream.AccountID)
	if err != nil {
		return nil, &awswire.Error{Code: "Lambda.AssumeRoleAccessDenied", Message: "Unable to assume the configured Lambda processing role: " + err.Error(), StatusCode: 400}
	}
	out, _, rejected := a.Functions.Invoke(ctx, &api.InvokeInput{
		FunctionName:   new(api.NamespacedFunctionName(functionARN)),
		InvocationType: new(api.InvocationType("RequestResponse")),
		Payload:        api.Blob(payload),
	})
	return out, rejected
}
