package lambda

import (
	"context"
	"encoding/json"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// recordInvocation owns the requested-versus-selected distinction. Admission
// records the version selected then; a later async attempt may resolve another.
func (s *Service) recordInvocation(ctx context.Context, name string, in *api.InvokeInput, wire *awswire.Error, selectedVersion string) error {
	if s.apiEvents == nil {
		return nil
	}
	call, err := projectLambdaCall(ctx, name, in, nil, wire)
	if err != nil {
		return err
	}
	scope := scopeFor(ctx)
	if in != nil {
		ref, invalid := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
		if invalid == nil {
			scope = ref.Scope
			call.EventResources = invocationResources(ref.FunctionKey)
			kind := value(in.InvocationType)
			if kind == "" {
				kind = "RequestResponse"
			}
			parameters := map[string]string{"functionName": ref.ARN(), "invocationType": kind}
			if ref.Qualifier != "" {
				parameters["qualifier"] = ref.Qualifier
			}
			call.RequestParameters, err = json.Marshal(parameters)
			if err != nil {
				return err
			}
			if wire == nil && selectedVersion != "" {
				additional := map[string]string{"functionVersion": ref.FunctionKey.ARN() + ":" + selectedVersion}
				if kind == "RequestResponse" {
					additional["customerEniId"] = ""
				}
				call.AdditionalEventData, err = json.Marshal(additional)
				if err != nil {
					return err
				}
			}
		}
	}
	// Native malformed JSON has no API error fields despite its HTTP400. No
	// customer payload or runtime response body belongs in these audit records.
	if wire != nil && wire.Code == "InvalidRequestContentException" {
		call.RequestParameters, call.AdditionalEventData = nil, nil
		call.ErrorCode, call.ErrorMessage = "", ""
	}
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, call)
}

func invocationResources(key FunctionKey) []journal.APIEventResource {
	return []journal.APIEventResource{{AccountID: key.Account, Type: "AWS::Lambda::Function", ARN: key.ARN()}}
}

func invocationAuditContext(ctx context.Context, v InvocationRecord) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.Account, Region: v.Key.Region, RequestID: v.RequestID, ParentEventID: v.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "lambda.amazonaws.com"}, SourceIP: "lambda.amazonaws.com", UserAgent: "lambda.amazonaws.com"})
}

func (s *Service) recordExecution(ctx context.Context, v InvocationRecord, version uint64, admitted bool) error {
	if s.apiEvents == nil {
		return nil
	}
	parameters, err := json.Marshal(map[string]string{"functionName": v.FunctionARN, "sourceArn": v.FunctionARN, "sourceAccount": v.Key.Account, "logType": "None", "contentType": "application/json"})
	if err != nil {
		return err
	}
	data := map[string]string{"functionVersion": v.Key.ARN() + ":" + versionName(version)}
	if admitted {
		data["customerEniId"] = ""
	}
	additional, err := json.Marshal(data)
	if err != nil {
		return err
	}
	// The native shared ID is not the acceptance event ID. One retained request
	// groups dispatch attempts, including throttles, without a second ledger.
	return s.apiEvents.Record(invocationAuditContext(ctx, v), journal.Envelope{At: s.clock.Now(), Partition: v.Key.Partition, AccountID: v.Key.Account, Region: v.Key.Region}, journal.APICallCompleted{
		EventSource: "lambda.amazonaws.com", EventName: "InvokeExecution", Category: journal.CategoryData, SharedEventID: v.ID,
		RequestParameters: parameters, AdditionalEventData: additional, EventResources: invocationResources(v.Key),
	})
}

// Native deletion-before-entry emits AWSService Invoke with empty parameters
// and no errorCode. This is a failed lookup, not InvokeExecution or a handler
// entry; only the separately captured retry-zero terminal reports status404.
func (s *Service) recordMissingInvocation(ctx context.Context, v InvocationRecord) error {
	if s.apiEvents == nil {
		return nil
	}
	return s.apiEvents.Record(invocationAuditContext(ctx, v), journal.Envelope{At: s.clock.Now(), Partition: v.Key.Partition, AccountID: v.Key.Account, Region: v.Key.Region}, journal.APICallCompleted{
		EventSource: "lambda.amazonaws.com", EventName: "Invoke", Category: journal.CategoryData, SharedEventID: v.ID, EventResources: invocationResources(v.Key),
	})
}
