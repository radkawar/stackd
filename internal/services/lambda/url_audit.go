package lambda

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"stackd/iam/policy"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/journal"
)

func (s *Service) recordFunctionURLInvocation(ctx context.Context, ref FunctionReference, selectedVersion string) error {
	if s.apiEvents == nil {
		return nil
	}
	// Both buffered and streaming native URLs produce Invoke data events, not
	// InvokeFunctionUrl or InvokeWithResponseStream. Admission failures and CORS
	// interception do not reach the underlying invocation.
	call, err := projectLambdaCall(ctx, "Invoke", &api.InvokeInput{
		FunctionName:   new(api.NamespacedFunctionName(ref.ARN())),
		InvocationType: new(api.InvocationType("RequestResponse")),
		LogType:        new(api.LogType("None")),
	}, nil, nil)
	if err != nil {
		return err
	}
	call.EventResources = invocationResources(ref.FunctionKey)
	call.AdditionalEventData, err = json.Marshal(map[string]string{"functionVersion": ref.FunctionKey.ARN() + ":" + selectedVersion})
	if err != nil {
		return err
	}
	metadata := awsctx.FromContext(ctx)
	if metadata.AccountID == policy.AnonymousAccountID {
		// CloudTrail's anonymous identity differs from IAM's request context.
		call.Identity = journal.APIIdentity{Type: "AWSAccount", PrincipalID: "anonymous", AccountID: "aws"}
	}
	if metadata.AccountID != ref.Account {
		call.SharedEventID = uuid.NewString()
	}
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: ref.Partition, AccountID: ref.Account, Region: ref.Region}, call)
}
