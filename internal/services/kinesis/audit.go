package kinesis

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

var auditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Data":         {Mode: awsapi.OmitField},
	"Records.Data": {Mode: awsapi.OmitField},
}}

var auditPutRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Data":                      {Mode: awsapi.OmitField},
	"Records":                   {Mode: awsapi.OmitField},
	"PartitionKey":              {Mode: awsapi.OmitField},
	"ExplicitHashKey":           {Mode: awsapi.OmitField},
	"SequenceNumberForOrdering": {Mode: awsapi.OmitField},
}}

var auditConsumerResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Consumer.ConsumerCreationTimestamp": {TimeLayout: "Jan 2, 2006, 3:04:05 PM"},
}}

// TODO: Comeback — capture account-setting and warm-throughput audit projections;
// probes deliberately exclude these cost-changing commands.
func auditProjection(action string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement, Request: auditRequest}
	p.ReadOnly = strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Get")
	switch action {
	case "GetRecords", "GetShardIterator", "SubscribeToShard":
		p.Category, p.ReadOnly = journal.CategoryData, true
	case "PutRecord", "PutRecords":
		// Native delivered events classify even record writes as read-only.
		p.Category, p.ReadOnly, p.Request = journal.CategoryData, true, auditPutRequest
	case "RegisterStreamConsumer":
		p.Response = &auditConsumerResponse
	case "EnableEnhancedMonitoring", "DisableEnhancedMonitoring", "UpdateShardCount":
		p.Response = &awsapi.DocumentProjection{}
	}
	// Data responses are explicitly null, including SubscribeToShard: audit
	// projection must never traverse its live EventStream or record frames.
	return p
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, ok := awscatalog.LookupService("kinesis")
	if !ok {
		return errors.New("kinesis audit service metadata is missing")
	}
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	call, err := auditProjection(action).Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	// Decode only the already-sanitized generated projection. This also retains
	// resource selectors for binding/admission failures without a callContext.
	var request map[string]any
	if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
		return err
	}
	scope := scopeFor(ctx)
	denied := rejected != nil && rejected.Code == "AccessDeniedException"
	put := action == "PutRecord" || action == "PutRecords"
	missingPut := put && rejected != nil && rejected.Code == "ResourceNotFoundException"
	if resource, ok := auditResource(ctx, action, request); ok {
		scope = resource.Scope
		name, _ := request["streamName"].(string)
		if action == "GetRecords" && denied && request["streamARN"] == nil {
			_, name, _ = strings.Cut(resource.ARN, ":stream/")
		}
		call.EventResources = auditEventResources(name, resource, call.Category == journal.CategoryData && !denied && !missingPut)
		if !denied {
			call.Resources = auditLookupResources(action, request, out, resource)
		}
		if put && !denied {
			delete(request, "streamName")
			request["streamARN"] = resource.ARN
			if missingPut {
				unresolved := auditNameResource(resource, "null")
				call.EventResources = append(call.EventResources, unresolved)
				request["streamARN"] = unresolved.ARN
			}
			call.RequestParameters, err = json.Marshal(request)
			if err != nil {
				return err
			}
		}
	}
	if denied {
		call.ErrorCode = "AccessDenied"
	}
	if denied || action == "DescribeLimits" || action == "DescribeAccountSettings" {
		call.RequestParameters = json.RawMessage("null")
	}
	// The command owns the transaction and reservation. The common recorder
	// supplies verified caller identity, request metadata and causal context.
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

func auditResource(ctx context.Context, action string, request map[string]any) (ResourceKey, bool) {
	// Explicit consumer/resource selectors must precede the stream remembered
	// while opening an engine. Resolving a parent never changes the target ARN.
	for _, field := range []string{"consumerARN", "resourceARN"} {
		if resource, _ := request[field].(string); resource != "" {
			return auditResourceARN(ctx, resource)
		}
	}
	// Name selection records a versionless consumer resource, not the
	// incarnation returned by the public description.
	if action == "DescribeStreamConsumer" || action == "DeregisterStreamConsumer" {
		name, _ := request["consumerName"].(string)
		streamARN, _ := request["streamARN"].(string)
		if name != "" {
			if key, err := streamKey(ctx, "", streamARN); err == nil {
				return ResourceKey{Scope: key.Scope, ARN: key.ARN() + "/consumer/" + name}, true
			}
		}
	}
	if call := currentCall(ctx); call != nil && call.action == action {
		if resource, ok := auditResourceARN(ctx, call.resource.ARN); ok {
			return resource, true
		}
		if call.stream != nil {
			return ResourceKey{Scope: call.stream.Key.Scope, ARN: call.stream.Key.ARN()}, true
		}
	}
	name, _ := request["streamName"].(string)
	resource, _ := request["streamARN"].(string)
	key, err := streamKey(ctx, name, resource)
	if err != nil {
		return ResourceKey{}, false
	}
	return ResourceKey{Scope: key.Scope, ARN: key.ARN()}, true
}

func auditResourceARN(ctx context.Context, resource string) (ResourceKey, bool) {
	if strings.Contains(resource, "/consumer/") {
		key, err := consumerKey(ctx, resource)
		if err != nil {
			return ResourceKey{}, false
		}
		return ResourceKey{Scope: key.Stream.Scope, ARN: key.ARN()}, true
	}
	key, err := streamKey(ctx, "", resource)
	if err != nil {
		return ResourceKey{}, false
	}
	return ResourceKey{Scope: key.Scope, ARN: key.ARN()}, true
}

func auditEventResources(name string, resource ResourceKey, data bool) []journal.APIEventResource {
	kind := "AWS::Kinesis::Stream"
	if strings.Contains(resource.ARN, "/consumer/") {
		kind = "AWS::Kinesis::StreamConsumer"
	}
	canonical := journal.APIEventResource{AccountID: resource.Scope.AccountID, Type: kind, ARN: resource.ARN}
	if name == "" {
		return []journal.APIEventResource{canonical}
	}
	// AWS's name-selected audit display puts the name in the account slot and
	// omits accountId. Successful data events also retain canonical identity.
	// These measured display values never enter resource lookup or IAM.
	display := auditNameResource(resource, name)
	if data {
		return []journal.APIEventResource{display, canonical}
	}
	return []journal.APIEventResource{display}
}

func auditNameResource(resource ResourceKey, name string) journal.APIEventResource {
	return journal.APIEventResource{Type: "AWS::Kinesis::Stream", ARN: "arn:" + resource.Scope.Partition + ":kinesis:" + resource.Scope.Region + ":" + name + ":stream/null"}
}

func auditLookupResources(action string, request map[string]any, out any, resource ResourceKey) []journal.APIResource {
	switch action {
	case "DescribeStream", "DescribeStreamSummary", "DescribeStreamConsumer", "ListShards", "ListStreamConsumers", "ListTagsForStream",
		"TagResource", "UntagResource", "ListTagsForResource", "PutResourcePolicy", "GetResourcePolicy", "DeleteResourcePolicy", "UpdateMaxRecordSize":
		return nil
	case "RegisterStreamConsumer":
		if result, ok := out.(*api.RegisterStreamConsumerOutput); ok && result != nil && result.Consumer != nil {
			return []journal.APIResource{
				{Type: "AWS::Kinesis::Stream", Name: resource.ARN},
				{Type: "AWS::Kinesis::StreamConsumer", Name: value(result.Consumer.ConsumerName)},
				{Type: "AWS::Kinesis::StreamConsumer", Name: value(result.Consumer.ConsumerARN)},
			}
		}
	case "DeregisterStreamConsumer":
		if name, _ := request["consumerName"].(string); name != "" {
			streamARN, _ := request["streamARN"].(string)
			return []journal.APIResource{
				{Type: "AWS::Kinesis::Stream", Name: streamARN},
				{Type: "AWS::Kinesis::StreamConsumer", Name: name},
			}
		}
	}
	kind := "AWS::Kinesis::Stream"
	if strings.Contains(resource.ARN, "/consumer/") {
		kind = "AWS::Kinesis::StreamConsumer"
	}
	name, _ := request["streamName"].(string)
	if name == "" {
		name = resource.ARN
	}
	lookup := journal.APIResource{Type: kind, Name: name}
	if action == "StartStreamEncryption" || action == "StopStreamEncryption" {
		keyID, _ := request["keyId"].(string)
		return []journal.APIResource{lookup, {Type: "AWS::KMS::Key", Name: keyID}}
	}
	return []journal.APIResource{lookup}
}
