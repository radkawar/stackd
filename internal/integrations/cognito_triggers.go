package integrations

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cognitoidp"
)

type CognitoTriggerLambdaCommands interface {
	Invoke(context.Context, *api.InvokeInput) (*api.InvokeOutput, string, *awswire.Error)
}

// CognitoTriggers delegates execution and current resource-policy authorization
// to native Lambda; the user's credentials never authorize this service invoke.
type CognitoTriggers struct{ Functions CognitoTriggerLambdaCommands }

func (a CognitoTriggers) InvokeTrigger(ctx context.Context, pool cognitoidp.PoolKey, functionARN string, payload []byte) ([]byte, error) {
	if a.Functions == nil {
		return nil, &awswire.Error{Code: "UnexpectedLambdaException", Message: "Native Lambda execution is not configured.", StatusCode: 400}
	}
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: pool.Partition, AccountID: pool.AccountID, Region: pool.Region,
		RequestID: uuid.NewString(), ParentEventID: apievents.EventID(ctx), TraceHeader: origin.TraceHeader,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "cognito-idp.amazonaws.com", SourceARN: pool.ARN(), Type: "AWSService"},
		SourceIP:         "cognito-idp.amazonaws.com", UserAgent: "cognito-idp.amazonaws.com", InvokedBy: "cognito-idp.amazonaws.com", TransportKnown: true, SecureTransport: true,
	})
	out, _, rejected := a.Functions.Invoke(ctx, &api.InvokeInput{FunctionName: new(api.NamespacedFunctionName(functionARN)), InvocationType: new(api.InvocationType("RequestResponse")), Payload: api.Blob(payload)})
	if rejected != nil {
		return nil, &awswire.Error{Code: "UnexpectedLambdaException", Message: "Unable to invoke Cognito Lambda trigger: " + rejected.Message, StatusCode: 400}
	}
	if out == nil {
		return nil, &awswire.Error{Code: "UnexpectedLambdaException", Message: "Lambda trigger invocation returned no result.", StatusCode: 400}
	}
	if out.FunctionError != nil && string(*out.FunctionError) != "" {
		var details struct {
			ErrorMessage string `json:"errorMessage"`
		}
		_ = json.Unmarshal(out.Payload, &details)
		if details.ErrorMessage == "" {
			details.ErrorMessage = "Lambda function rejected the request."
		}
		return nil, &awswire.Error{Code: "UserLambdaValidationException", Message: fmt.Sprintf("Cognito Lambda trigger failed with error %s", details.ErrorMessage), StatusCode: 400}
	}
	return out.Payload, nil
}

var _ cognitoidp.TriggerInvoker = CognitoTriggers{}
