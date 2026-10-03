package integrations

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	"stackd/internal/authorization"
	lambdaapi "stackd/internal/awsapi/lambda"
	snsapi "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/eventbridge"
)

func (a *AppConfigEffects) InvokeExtension(ctx context.Context, scope appconfig.Scope, action appconfig.ExtensionAction, payload []byte) ([]byte, error) {
	target, err := arn.Parse(action.URI)
	if err != nil || target.Partition != scope.Partition {
		return nil, appConfigFailure("Invalid extension action URI.")
	}
	source := awsctx.FromContext(ctx).ServicePrincipal.SourceARN
	if action.RoleARN != "" {
		ctx, err = a.roleContext(ctx, scope, action.RoleARN, source)
		if err != nil {
			return nil, err
		}
	} else {
		origin := awsctx.FromContext(ctx)
		ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: appConfigPrincipal(scope, source)})
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Region = target.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	switch target.Service {
	case "lambda":
		if a.Functions == nil {
			return nil, fmt.Errorf("AppConfig Lambda owner is unavailable")
		}
		invocationType := lambdaapi.InvocationType("RequestResponse")
		if strings.HasPrefix(action.Point, "ON_") {
			// Lambda owns durable asynchronous admission, retries and real runtime
			// execution. An ON_* payload is not a synchronous mutation response.
			invocationType = "Event"
		}
		out, _, rejected := a.Functions.Invoke(ctx, &lambdaapi.InvokeInput{FunctionName: new(lambdaapi.NamespacedFunctionName(action.URI)), InvocationType: &invocationType, Payload: payload})
		if rejected != nil {
			return nil, rejected
		}
		if appConfigString(out.FunctionError) != "" {
			return nil, appConfigFailure("Extension Lambda failed: " + string(out.Payload))
		}
		return out.Payload, nil
	case "sns":
		_, err = appConfigCommand(ctx, a.SNS, "sns", "Publish", &snsapi.PublishInput{TopicArn: new(snsapi.TopicARN(action.URI)), Message: new(snsapi.Message(payload))})
		return nil, err
	case "sqs":
		// Queue URLs are routing inputs, not cached queue metadata. SendMessage owns
		// resource existence, KMS and current resource/identity policy evaluation.
		suffix := "amazonaws.com"
		if scope.Partition == "aws-cn" {
			suffix = "amazonaws.com.cn"
		}
		queueURL := "https://sqs." + target.Region + "." + suffix + "/" + target.AccountID + "/" + target.Resource
		_, err = appConfigCommand(ctx, a.SQS, "sqs", "SendMessage", &sqsapi.SendMessageInput{QueueUrl: new(sqsapi.String(queueURL)), MessageBody: new(sqsapi.String(payload))})
		return nil, err
	case "events":
		if target.Resource != "event-bus/default" || target.AccountID != scope.AccountID {
			return nil, appConfigFailure("Extension EventBridge URI must identify this account's default event bus.")
		}
		if a.Events == nil || a.Clock == nil || a.Roles.Authorizer == nil {
			return nil, fmt.Errorf("AppConfig EventBridge owner is unavailable")
		}
		now := a.Clock.Now()
		if rejected := a.Roles.Authorizer.Authorize(ctx, authorization.Request{Action: "events:PutEvents", ResourceARN: action.URI, Context: map[string][]string{"events:source": {"aws.appconfig"}, "events:detail-type": {"AppConfig Deployment Event"}}, EvaluationTime: &now}); rejected != nil {
			return nil, rejected
		}
		event := eventbridge.EventRecord{ID: uuid.NewString(), Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: target.Region}, Name: "default"}, Source: "aws.appconfig", DetailType: "AppConfig Deployment Event", Detail: string(payload), Time: now, Account: scope.AccountID, RequestID: awsctx.FromContext(ctx).RequestID}
		return nil, a.Events.PublishEvent(ctx, event)
	default:
		return nil, appConfigFailure("Unsupported extension destination: " + target.Service)
	}
}
