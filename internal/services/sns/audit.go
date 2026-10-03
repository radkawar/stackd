package sns

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Native topic controls and PublishBatch are retained in the SNS audit capture.
// Publish redaction/response fields also follow the official SNS CloudTrail
// example. Remaining management projections use the generated public shapes;
// they are not additional claimed native observations.
func auditProjection(action string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement}
	p.ReadOnly = strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Check")
	switch action {
	case "Publish", "PublishBatch":
		p.Category = journal.CategoryData
		p.Response = &awsapi.DocumentProjection{}
		prefix := ""
		if action == "PublishBatch" {
			prefix = "PublishBatchRequestEntries."
		}
		p.Request.Fields = map[string]awsapi.FieldProjection{
			prefix + "Message":           {Mode: awsapi.RedactField},
			prefix + "Subject":           {Mode: awsapi.RedactField},
			prefix + "MessageAttributes": {Mode: awsapi.RedactValueField},
		}
	case "CreateTopic", "Subscribe", "ConfirmSubscription":
		p.Response = &awsapi.DocumentProjection{}
	}
	if action == "ConfirmSubscription" {
		p.Request.Fields = map[string]awsapi.FieldProjection{"Token": {Mode: awsapi.RedactValueField, Redaction: "REDACTED"}}
	}
	return p
}

func (s *Service) recordCall(ctx context.Context, action string, input, output any, rejected *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	caller := awsctx.FromContext(ctx)
	// SNS does not log unauthenticated endpoint confirmation or cancellation.
	if caller.PrincipalARN == "" && (action == "ConfirmSubscription" || action == "Unsubscribe") {
		return nil
	}
	model, _ := awscatalog.LookupService("sns")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	call, err := auditProjection(action).Call(model, op, input, output, rejected)
	if err != nil {
		return err
	}
	call.APIVersion = model.Version
	data := action == "Publish" || action == "PublishBatch"
	if data {
		call.EventID = apievents.EventID(ctx)
	}
	// Resource member accessors are generated from Smithy input shapes. New
	// topic operations do not require another hand-maintained DTO type switch.
	var resource string
	subscription := false
	switch in := input.(type) {
	case interface{ ResourceTopicARN() *string }:
		resource = value(in.ResourceTopicARN())
	case interface{ ResourceARN() *string }:
		resource = value(in.ResourceARN())
	case interface{ ResourceSubscriptionARN() *string }:
		resource = value(in.ResourceSubscriptionARN())
		subscription = true
	}
	scope := scopeFor(ctx)
	owner := ""
	if parsed, err := arn.Parse(resource); err == nil && parsed.Service == "sns" && parsed.AccountID != "" {
		owner = parsed.AccountID
		kind, account := "AWS::SNS::Topic", owner
		if subscription {
			// Native subscription actions expose the full ARN as a platform
			// endpoint, with the caller account rather than the ARN's account.
			kind, account = "AWS::SNS::PlatformEndpoint", scope.AccountID
		}
		if action == "ConfirmSubscription" {
			account = scope.AccountID
		}
		call.EventResources = []journal.APIEventResource{{AccountID: account, Type: kind, ARN: resource}}
	}
	var cause *awswire.Error
	if rejected != nil {
		cause, _ = rejected.Cause.(*awswire.Error)
	}
	iamDenied := rejected != nil && (rejected.Code == "AccessDenied" || cause != nil && cause.Code == "AccessDenied")
	if iamDenied {
		call.ErrorCode = "AccessDenied"
		call.RequestParameters, call.ResponseElements = nil, nil
	}
	crossAccount := owner != "" && owner != scope.AccountID && !subscription &&
		action != "ConfirmSubscription" && (data || rejected == nil || iamDenied)
	if crossAccount {
		call.SharedEventID = identifier()
		if iamDenied {
			call.EventResources[0].AccountID = "HIDDEN_DUE_TO_SECURITY_REASONS"
		}
	}
	envelope := journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}
	if err := s.apiEvents.Record(ctx, envelope, call); err != nil {
		return err
	}
	if !crossAccount {
		return nil
	}
	// Caller and owner observe one request, but distinct event identities. The
	// owner copy must not expose the foreign actor's session or access key.
	envelope.AccountID = owner
	call.EventID = ""
	call.Identity = journal.APIIdentity{Type: "AWSAccount", AccountID: scope.AccountID, PrincipalID: caller.PrincipalID}
	call.EventResources[0].AccountID = owner
	return s.apiEvents.Record(ctx, envelope, call)
}

func finishCall[O any](s *Service, ctx context.Context, action string, input any, output **O, rejected **awswire.Error, read bool) {
	if *rejected == nil && !read {
		return
	}
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := s.recordCall(completion, action, input, *output, *rejected); err != nil {
		*output, *rejected = nil, wireError(err)
	}
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
